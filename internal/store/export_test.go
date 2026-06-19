package store

import "net/http"

var (
	ValidateDownloadURL = validateDownloadURL
	StagingEnvVar       = stagingEnvVar
)

func SetHTTPDo(fn func(req *http.Request) (*http.Response, error)) (restore func()) {
	saved := httpDo
	httpDo = fn
	return func() { httpDo = saved }
}

func SetBulkDo(fn func(req *http.Request) (*http.Response, error)) (restore func()) {
	saved := bulkDo
	bulkDo = fn
	return func() { bulkDo = saved }
}
