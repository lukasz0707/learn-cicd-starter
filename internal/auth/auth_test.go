package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - No 'ApiKey' prefix",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer someapikey")
				return h
			}(),
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Malformed Authorization Header - Missing API Key",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			expectedKey:   "",
			expectedError: ErrMalformedAuthHeader,
		},
		{
			name: "Valid Authorization Header",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey myvalidapikey")
				return h
			}(),
			expectedKey:   "myvalidapikey",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			assert.Equal(t, tt.expectedKey, apiKey, "unexpected API key")
			assert.ErrorIs(t, err, tt.expectedError, "unexpected error")
		})
	}
}
