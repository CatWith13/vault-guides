package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"

	"strconv"
)

// Factory configures and returns Mock backends
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{
		store: make(map[string][]byte), //key is string, value is byte[]
		versionToPID: make(map[string]string),
	}

	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(mockHelp),
		BackendType: logical.TypeLogical,
	}

	b.Backend.Paths = append(b.Backend.Paths, b.paths()...)

	if conf == nil {
		return nil, fmt.Errorf("configuration passed into backend is nil")
	}

	b.Backend.Setup(ctx, conf)

	return b, nil
}

// backend wraps the backend framework and adds a map for storing key value pairs
type backend struct {
	*framework.Backend

	store map[string][]byte
	
	versionToPID map[string]string	//current subversion number regarding to version
	
}

func (b *backend) paths() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: framework.MatchAllRegex("path"),

			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type:        framework.TypeString,
					Description: "Specifies the path of the secret.",
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRead,
					Summary:  "Retrieve the secret from the map.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
					Summary:  "Store a secret at the specified location.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDelete,
					Summary:  "Deletes the secret at the specified location.",
				},
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleList,
					Summary:  "List secret entries at the specified location",
				},

			},

			ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) handleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	return out != nil, nil
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	out, err := req.Storage.Get(ctx, req.ClientToken+"/"+path)
	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}
	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}
	
	// Generate the response
	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func (b *backend) handleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	// Check to make sure that kv pairs provided
	if len(req.Data) == 0 {
		return nil, fmt.Errorf("data must be provided to store in secret")
	}

	path := data.Get("path").(string)

	// JSON encode the data
	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, errwrap.Wrapf("json encoding failed: {{err}}", err)
	}
	//-------------------------------------------------------------
	
	s_buf := strings.Split(string(buf[:]), "\"") //s_buf[1] is proposalID; s_buf[3] is value
	_, exist := b.versionToPID[path]
	storedPID,_ := strconv.Atoi(b.versionToPID[path])

	if(s_buf[3] == "0"){	//Phase 1 -- PROMISE request 
		if(exist){	//promised to someone or was written
			proposedPID,_ := strconv.Atoi(s_buf[1])	
			if(storedPID < proposedPID){
				//read path to confirm whether it exists
				out, err := req.Storage.Get(ctx, req.ClientToken+"/"+path)
				if (err != nil || out == nil) {
					b.versionToPID[path] = s_buf[1]
					return nil, errwrap.Wrapf("promise:"+ s_buf[1],nil)
				}

				// Decode the data
				var rawData map[string]interface{}
				jsonutil.DecodeJSON(out.Value, &rawData)
				b.versionToPID[path] = s_buf[1]
				
				storedData, _ := json.Marshal(rawData)
				return nil, errwrap.Wrapf("existing:"+ string(storedData), nil)
				
			}else{//omit the smaller proposal
				return nil, errwrap.Wrapf("higherProposal:"+b.versionToPID[path], nil)
			}
		}else{	//this version was not written before
			b.versionToPID[path] = s_buf[1] 
			return nil, errwrap.Wrapf("promise:"+ s_buf[1],nil)
		}	
	}else{	//Phase 2 -- ACCEPT request 
		if(exist){ 		
			proposedPID,_ := strconv.Atoi(s_buf[1])
			if (storedPID > proposedPID){
				return nil, errwrap.Wrapf("higherProposal:"+b.versionToPID[path],nil)
			}else{
				//can write now
				s_buf_accept := strings.Split(string(s_buf[3]), ",")
				subpath := [3] string {"", "-share", "-ctxt",}
				for i:=0; i<3; i++ {
					entry := &logical.StorageEntry{
						Key:   req.ClientToken + "/" + path + subpath[i],
						Value: []byte("{\""+ s_buf[1] + "\":\"" +s_buf_accept[i]+"\"}"),
					}
					if err := req.Storage.Put(ctx, entry); err != nil {
						return nil, errwrap.Wrapf("failed to write: {{err}}", err)
					}
				}
				b.versionToPID[path] = s_buf[1]
				return nil, nil
			}
		}else{
			//can write now
			s_buf_accept := strings.Split(string(s_buf[3]), ",")
			subpath := [3] string {"", "-share", "-ctxt",}
			for i:=0; i<3; i++ {
				entry := &logical.StorageEntry{
					Key:   req.ClientToken + "/" + path + subpath[i],
					Value: []byte("{\""+ s_buf[1] + "\":\"" +s_buf_accept[i]+"\"}"),
				}
				if err := req.Storage.Put(ctx, entry); err != nil {
					return nil, errwrap.Wrapf("failed to write: {{err}}", err)
				}
			}
			b.versionToPID[path] = s_buf[1]
			return nil, nil
		}
	}
}


func (b *backend) handleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) { //need to delete path under a secret engine 1-by-1
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)

	// Remove entry for specified path
	//delete(b.store, path)	//seems not work
	if err := req.Storage.Delete(ctx, req.ClientToken+"/"+path); err != nil {
		return nil, err
	}
	return nil, nil
}



//use list cli to get the latest version
func (b *backend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	path := data.Get("path").(string)
	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	keys, err := req.Storage.List(ctx, req.ClientToken+"/"+path)
	if err != nil {
		return nil, err
	}
	
	var max_version int = 0
	for _, key := range keys {
		var temp, _ = strconv.Atoi(strings.TrimPrefix(key, req.ClientToken+"/"))
		if(temp > max_version){
			max_version = temp
		}
	}
	strippedKeys := make([]string, 1)
	strippedKeys[0] = strconv.Itoa(max_version)
	
	return logical.ListResponse(strippedKeys), nil
}


const mockHelp = `
The Mock backend is a dummy secrets backend that stores kv pairs in a map.
`
