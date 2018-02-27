package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"path"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)


const (
	Version = "1.0"
)

var (
	secureTransport *http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			ClientSessionCache: tls.NewLRUClientSessionCache(1000),
		},
		TLSHandshakeTimeout: 30 * time.Second,
		MaxIdleConnsPerHost: 4,
		DisableCompression:  true,
	}

	insecureTransport *http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(1000),
		},
		TLSHandshakeTimeout: 30 * time.Second,
		MaxIdleConnsPerHost: 4,
		DisableCompression:  true,
	}
)


func main() {
	http.HandleFunc("/2/", handler)
	http.HandleFunc("/", handler_root)

	port := os.Getenv("PORT")
	//log.Debug("port:%d", port)

	err := http.ListenAndServe(":" + port, nil)
	if err != nil {
		panic(err)
	}
}

func ReadRequest(r io.Reader) (req *http.Request, err error) {
	req = new(http.Request)

	scanner := bufio.NewScanner(r)
	if scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			err = fmt.Errorf("Invaild Request Line: %#v", line)
			return
		}

		req.Method = parts[0]
		req.RequestURI = parts[1]
		req.Proto = "HTTP/1.1"
		req.ProtoMajor = 1
		req.ProtoMinor = 1

		if req.URL, err = url.Parse(req.RequestURI); err != nil {
			return
		}
		req.Host = req.URL.Host

		req.Header = http.Header{}
	}

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		req.Header.Add(key, value)
	}

	if err = scanner.Err(); err != nil {
		// ignore
	}

	if cl := req.Header.Get("Content-Length"); cl != "" {
		if req.ContentLength, err = strconv.ParseInt(cl, 10, 64); err != nil {
			return
		}
	}

	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.Get("Host")
	}

	return
}

func httpError(rw http.ResponseWriter, err string, code int) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "HTTP/1.1 %d\r\n", code)
	fmt.Fprintf(rw, "Content-Length: %d\r\n", len(err))
	fmt.Fprintf(rw, "Content-Type: text/plain\r\n")
	io.WriteString(rw, "\r\n")
	io.WriteString(rw, err)
}


func handler(rw http.ResponseWriter, req *http.Request) {
	var err error

	var hdrLen uint16
	if err := binary.Read(req.Body, binary.BigEndian, &hdrLen); err != nil {
		httpError(rw, "fetch header len:"+err.Error(), http.StatusBadRequest)
		return
	}
	req1, err := ReadRequest(io.LimitReader(req.Body, int64(hdrLen)))
	if err != nil {
		httpError(rw, "fetch header:"+err.Error(), http.StatusBadRequest)
		return
	}

	var bodyLen uint32
	if err := binary.Read(req.Body, binary.BigEndian, &bodyLen); err != nil {
		httpError(rw, "fetch body len:"+err.Error(), http.StatusBadRequest)
		return
	}
	r := io.LimitReader(req.Body, int64(bodyLen))
	data, err := ioutil.ReadAll(r)
	if err != nil {
		httpError(rw, "fetch body:"+err.Error(), http.StatusBadRequest)
		return
	}

	if req1.Host != "center.xx-net.net" && req1.Host != "dns.xx-net.net" && req1.Host != "scan1.xx-net.net"  {
		httpError(rw, "fetch Host:"+req1.Host+" deny.", http.StatusBadRequest)
		return
	}

	req1.Body = ioutil.NopCloser(bytes.NewReader(data))
	req1.ContentLength = int64(len(data))
	req1.Header.Set("Content-Length", strconv.FormatInt(req1.ContentLength, 10))
	req1.Header.Set("x-forwarded-for", req.RemoteAddr)
	req1.Header.Set("xx-forwarded-for", req.RemoteAddr)
	req1.Header.Set("x-front", "heroku")

	// log.Printf("%s \"%s %s %s\" - -", req.RemoteAddr, req1.Method, req1.URL.String(), req1.Proto)

	var resp *http.Response
	resp, err = insecureTransport.RoundTrip(req1)
	if err != nil {
		httpError(rw, "fetch remote:"+err.Error(), http.StatusBadGateway)
		return
	}

	defer resp.Body.Close()

	// rewise resp.Header
	resp.Header.Del("Transfer-Encoding")
	if resp.ContentLength > 0 {
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}

	var w io.Writer = rw
	rw.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "%s %s\r\n", resp.Proto, resp.Status)
	resp.Header.Write(w)
	io.WriteString(w, "\r\n")
	io.Copy(w, resp.Body)
}

func is_dir(name string)(bool){
    fi, err := os.Stat(name)
    if err != nil {
        return false
    }
    switch mode := fi.Mode(); {
    case mode.IsDir():
        return true
    }
    return false
}

func handler_root(w http.ResponseWriter, r *http.Request) {
    p := "html/" + r.URL.Path
    if is_dir(p) {
        p = path.Join(p, "index.html")
    }
    data, err := ioutil.ReadFile(p)
    if err != nil {
        log.Printf(p + " not found.")
        http.NotFound(w, r)
        return
    }

    http.ServeContent(w, r, r.URL.Path, time.Now(), bytes.NewReader(data))
}