req
==============

req is a light weight golang http request library, and simple to the extreme.

# Quick Start
## Install
``` sh
go get github.com/imroc/req
```

## Talk is cheap, show me the CODE !!!
``` go
// GET
r, err := req.Get(url)
if err != nil {
	// handle error...
}
log.Println(r.String()) // print response body

// POST
header := req.Header{
	"Accept":        "application/json",
	"Authorization": "Basic YWRtaW46YWRtaW4=",
}
param := req.Param{
	"cmd":  "list_gopher",
	"city": "Chengdu",
}
r, _ = req.Post("http://foo.bar/api", header, param)
/*
	POST http://foo.bar/api HTTP/1.1
	Authorization:Basic YWRtaW46YWRtaW4=
	Accept:application/json
	Content-Type:application/x-www-form-urlencoded

	city=Chengdu&cmd=list_gopher

	HTTP/1.1 200 OK
	Content-Type:application/json; charset=UTF-8
	Date:Wed, 03 May 2017 09:39:27 GMT
	Content-Length:39

	{"code":0,"name":["imroc","yulibaozi"]}
*/
log.Printf("%+v", r)
r.ToJSON(&foo) // body --> struct or map
```