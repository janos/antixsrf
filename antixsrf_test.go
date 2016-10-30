// Copyright (c) 2015, 2016 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package antixsrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var validSetCookie = regexp.MustCompile(`^` + XSRFCookieName + `=[\w\d]{26};`)

func TestGenerate(t *testing.T) {
	r := httptest.NewRequest("", "/", nil)
	w := httptest.NewRecorder()

	Generate(w, r, "/some-path")

	setCookies, ok := w.HeaderMap["Set-Cookie"]
	if !ok {
		t.Error("no set-cookie header in response")
	}
	setCookie := setCookies[0]
	if !validSetCookie.MatchString(setCookie) {
		t.Errorf("set-cookie header %s does not start with %s= and contain a valid token", setCookie, XSRFCookieName)
	}
	p := "Path=/some-path"
	if !strings.Contains(setCookie, p) {
		t.Errorf("set-cookie header %s does contaon path part %s", setCookie, p)
	}
}

func TestGenerateSecure(t *testing.T) {
	r := httptest.NewRequest("", "https://localhost/", nil)
	w := httptest.NewRecorder()

	Generate(w, r, "/secure-path")

	setCookies, ok := w.HeaderMap["Set-Cookie"]
	if !ok {
		t.Error("no set-cookie header in response")
	}
	setCookie := setCookies[0]
	if !validSetCookie.MatchString(setCookie) {
		t.Errorf("set-cookie header %s does not start with %s= and contain a valid token", setCookie, XSRFCookieName)
	}
	p := "Path=/secure-path"
	if !strings.Contains(setCookie, p) {
		t.Errorf("set-cookie header %s does not contain path part %s", setCookie, p)
	}
	s := "Secure"
	if !strings.Contains(setCookie, s) {
		t.Errorf("set-cookie header %s does not contain secure part %s", setCookie, s)
	}
}

func TestVerifySafeMethods(t *testing.T) {
	for _, m := range safeMethods {
		r := httptest.NewRequest(m, "https://localhost/", nil)

		if err := Verify(r); err != nil {
			t.Errorf("method %s: got error %#v, expected nil", m, err)
		}
	}
}

func TestVerifyMissingReferer(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Del("Referer")

	if err := Verify(r); err != ErrNoReferer {
		t.Errorf("got error %#v, expected %#v", err, ErrNoReferer)
	}
}

func TestVerifyInvalidReferer(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://gopherpit.com/")

	if err := Verify(r); err != ErrInvalidReferer {
		t.Errorf("got error %#v, expected %#v", err, ErrInvalidReferer)
	}
}

func TestVerifyMissingCookie(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")

	if err := Verify(r); err != ErrMissingCookie {
		t.Errorf("got error %#v, expected %#v", err, ErrMissingCookie)
	}
}

func TestVerifyMissingToken(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")
	r.AddCookie(&http.Cookie{
		Name:  XSRFCookieName,
		Value: "",
	})

	if err := Verify(r); err != ErrMissingToken {
		t.Errorf("got error %#v, expected %#v", err, ErrMissingToken)
	}
}

func TestVerifyMissingHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")
	r.AddCookie(&http.Cookie{
		Name:  XSRFCookieName,
		Value: "xsrf123",
	})

	if err := Verify(r); err != ErrMissingHeader {
		t.Errorf("got error %#v, expected %#v", err, ErrMissingHeader)
	}
}

func TestVerifyInvalidToken(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")
	r.AddCookie(&http.Cookie{
		Name:  XSRFCookieName,
		Value: "xsrf123",
	})
	r.Header.Set(XSRFHeaderName, "xsrf")

	if err := Verify(r); err != ErrInvalidToken {
		t.Errorf("got error %#v, expected %#v", err, ErrInvalidToken)
	}
}

func TestVerify(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")
	r.AddCookie(&http.Cookie{
		Name:  XSRFCookieName,
		Value: "xsrf123",
	})
	r.Header.Set(XSRFHeaderName, "xsrf123")

	if err := Verify(r); err != nil {
		t.Errorf("got error %#v, expected %#v", err, nil)
	}
}

func TestVerifyForm(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")
	r.AddCookie(&http.Cookie{
		Name:  XSRFCookieName,
		Value: "xsrf123",
	})
	r.Form = url.Values(map[string][]string{XSRFFormFieldName: {"xsrf123"}})
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := Verify(r); err != nil {
		t.Errorf("got error %#v, expected %#v", err, nil)
	}
}

func TestVerifyFormMultipart(t *testing.T) {
	r := httptest.NewRequest("POST", "http://localhost/", nil)
	r.Header.Set("Referer", "http://localhost/")
	r.AddCookie(&http.Cookie{
		Name:  XSRFCookieName,
		Value: "xsrf123",
	})
	r.Form = url.Values(map[string][]string{XSRFFormFieldName: {"xsrf123"}})
	r.Header.Set("Content-Type", "multipart/form-data")

	if err := Verify(r); err != nil {
		t.Errorf("got error %#v, expected %#v", err, nil)
	}
}

func TestVerifyError(t *testing.T) {
	err := newError("test")

	if err.Error() != "test" {
		t.Errorf(`expected error string "test", got "%s"`, err.Error())
	}
}
