package req

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Header map[string]string
type Param map[string]string
type File struct {
	Filename string
	Formname string
	Source   io.Reader
}

var Client *http.Client
var defaultClient *http.Client
var defaultTransport *http.Transport
var regTextContentType = regexp.MustCompile("xml|json|text")

func init() {
	jar, _ := cookiejar.New(nil)
	defaultTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	defaultClient = &http.Client{
		Jar:       jar,
		Transport: defaultTransport,
		Timeout:   2 * time.Minute,
	}
}

type Req struct {
	req      *http.Request
	resp     *http.Response
	client   *http.Client
	reqBody  []byte
	respBody []byte
}

func EnableInsecureTLS(enable bool) {
	if defaultTransport.TLSClientConfig == nil {
		defaultTransport.TLSClientConfig = &tls.Config{}
	}
	defaultTransport.TLSClientConfig.InsecureSkipVerify = enable
}

func Do(method, rawurl string, v ...interface{}) (r *Req, err error) {
	if rawurl == "" {
		return nil, errors.New("req: url not specified")
	}
	req := &http.Request{
		Method:     method,
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	r = &Req{req: req}
	handleBody := func(body *Body) {
		if body == nil {
			return
		}
		req.Body = body.readCloser
		if body.contentType != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", body.contentType)
		}
		if body.bytes != nil {
			r.reqBody = body.bytes
			req.ContentLength = int64(len(body.bytes))
		}
	}

	var param []Param
	var file []File
	for _, p := range v {
		switch t := p.(type) {
		case Header:
			for key, value := range t {
				req.Header.Add(key, value)
			}
		case http.Header:
			req.Header = t
		case io.ReadCloser:
			req.Body = t
		case io.Reader:
			req.Body = ioutil.NopCloser(t)
		case *Body:
			handleBody(t)
		case Param:
			param = append(param, t)
		case *http.Client:
			r.client = t
		case File:
			file = append(file, t)
		}
	}

	if len(file) > 0 && (req.Method == "POST" || req.Method == "PUT") {
		pr, pw := io.Pipe()
		bodyWriter := multipart.NewWriter(pw)
		go func() {
			for _, f := range file {
				fileWriter, e := bodyWriter.CreateFormFile(f.Formname, filepath.Base(f.Filename))
				if e != nil {
					err = e
					return
				}
				//iocopy
				var src io.Reader
				if f.Source == nil {
					src, e = os.Open(f.Filename)
					if e != nil {
						err = e
						return
					}
				} else {
					src = f.Source
				}
				_, e = io.Copy(fileWriter, src)
				if e != nil {
					err = e
					return
				}

				if closer, ok := src.(io.Closer); ok {
					closer.Close()
				}
			}
			for _, p := range param {
				for key, value := range p {
					bodyWriter.WriteField(key, value)
				}
			}
			bodyWriter.Close()
			pw.Close()
		}()
		req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
		req.Body = ioutil.NopCloser(pr)
	} else if len(param) > 0 {
		params := make(url.Values)
		for _, p := range param {
			for key, value := range p {
				params.Add(key, value)
			}
		}
		paramStr := params.Encode()
		if method == "GET" {
			if strings.IndexByte(rawurl, '?') == -1 {
				rawurl = rawurl + "?" + paramStr
			} else {
				rawurl = rawurl + "&" + paramStr
			}
		} else {
			body := &Body{
				contentType: "application/x-www-form-urlencoded",
				bytes:       []byte(paramStr),
				readCloser:  ioutil.NopCloser(strings.NewReader(paramStr)),
			}
			handleBody(body)
		}
	}

	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	req.URL = u

	if r.client == nil {
		if Client != nil {
			r.client = Client
		} else {
			r.client = defaultClient
		}
	}

	resp, errDo := r.client.Do(req)
	if err != nil {
		return r, err
	}
	if errDo != nil {
		return r, errDo
	}
	r.resp = resp
	ct := resp.Header.Get("Content-Type")
	if ct == "" || regTextContentType.MatchString(ct) {
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return r, err
		}
		r.respBody = respBody
	}
	return r, nil
}

type Body struct {
	contentType string
	bytes       []byte
	readCloser  io.ReadCloser
}

func BodyXML(b interface{}) *Body {
	body := new(Body)
	switch v := b.(type) {
	case string:
		bf := bytes.NewBufferString(v)
		body.readCloser = ioutil.NopCloser(bf)
		body.bytes = []byte(v)
	case []byte:
		bf := bytes.NewBuffer(v)
		body.readCloser = ioutil.NopCloser(bf)
		body.bytes = v
	default:
		bs, err := xml.Marshal(body)
		if err != nil {
			return nil
		}
		bf := bytes.NewBuffer(bs)
		body.readCloser = ioutil.NopCloser(bf)
		body.bytes = bs
	}
	body.contentType = "text/xml"
	return body
}

func BodyJSON(b interface{}) *Body {
	body := new(Body)
	switch v := b.(type) {
	case string:
		bf := bytes.NewBufferString(v)
		body.readCloser = ioutil.NopCloser(bf)
		body.bytes = []byte(v)
	case []byte:
		bf := bytes.NewBuffer(v)
		body.readCloser = ioutil.NopCloser(bf)
		body.bytes = v
	default:
		bs, err := json.Marshal(body)
		if err != nil {
			return nil
		}
		bf := bytes.NewBuffer(bs)
		body.readCloser = ioutil.NopCloser(bf)
		body.bytes = bs
	}
	body.contentType = "text/json"
	return body
}

func (r *Req) Bytes() []byte {
	return r.respBody
}

func (r *Req) String() string {
	return string(r.respBody)
}

func (r *Req) ToJSON(v interface{}) error {
	return json.Unmarshal(r.respBody, v)
}

func (r *Req) ToXML(v interface{}) error {
	return xml.Unmarshal(r.respBody, v)
}

func (r *Req) ToFile(name string) error {
	file, err := os.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(file, r.resp.Body)
	if err != nil {
		return err
	}
	return nil
}

var regBlank = regexp.MustCompile(`\s+`)

func (r *Req) Format(s fmt.State, verb rune) {
	if r == nil || r.req == nil {
		return
	}
	req := r.req
	if s.Flag('+') { // include header and format pretty.
		fmt.Fprint(s, req.Method, " ", req.URL.String(), " ", req.Proto)
		for name, values := range req.Header {
			for _, value := range values {
				fmt.Fprint(s, "\n", name, ":", value)
			}
		}
		if len(r.reqBody) > 0 {
			fmt.Fprint(s, "\n\n", string(r.reqBody))
		}
		if r.resp != nil {
			resp := r.resp
			fmt.Fprint(s, "\n\n")
			fmt.Fprint(s, resp.Proto, " ", resp.Status) // e.g. HTTP/1.1 200 OK
			//header
			if len(resp.Header) > 0 {
				for name, values := range resp.Header {
					for _, value := range values {
						fmt.Fprintf(s, "\n%s:%s", name, value)
					}
				}
			}
			//body
			fmt.Fprint(s, "\n\n", string(r.respBody))
		}
	} else if s.Flag('-') { // keep all informations in one line.
		fmt.Fprint(s, req.Method, " ", req.URL.String())
		if len(r.reqBody) > 0 {
			str := regBlank.ReplaceAllString(string(r.reqBody), "")
			fmt.Fprint(s, str)
		}
		if str := string(r.reqBody); str != "" {
			str = regBlank.ReplaceAllString(str, "")
			fmt.Fprint(s, " ", str)
		}
	} else { // auto
		fmt.Fprint(s, req.Method, " ", req.URL.String())
		respBody := r.respBody
		if (len(r.reqBody) > 0 && bytes.IndexByte(r.reqBody, '\n') != -1) || (len(respBody) > 0 && bytes.IndexByte(respBody, '\n') != -1) { // pretty format
			if len(r.reqBody) > 0 {
				fmt.Fprint(s, "\n", string(r.reqBody))
			}
			if len(respBody) > 0 {
				fmt.Fprint(s, "\n", string(respBody))
			}
		} else {
			if len(r.reqBody) > 0 {
				fmt.Fprint(s, " ", string(r.reqBody))
			}
			if len(respBody) > 0 {
				fmt.Fprint(s, " ", string(respBody))
			}
		}
	}

}

func Get(url string, v ...interface{}) (*Req, error) {
	return Do("GET", url, v...)
}
func Post(url string, v ...interface{}) (*Req, error) {
	return Do("POST", url, v...)
}
