package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"pubapi/internal/response"
	"pubapi/internal/service"
)

type hashRequest struct {
	Text string `json:"text"`
	Algo string `json:"algo"` // md5|sha1|sha256|sha512|crc32; empty = all
}

// HashText handles POST /api/v1/util/hash
func (h *Handler) HashText(c *gin.Context) {
	var req hashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with a 'text' field.")
		return
	}
	if req.Algo == "" || req.Algo == "all" {
		response.OK(c, http.StatusOK, gin.H{"text": req.Text, "hashes": service.HashAll(req.Text)})
		return
	}
	sum, err := service.Hash(req.Algo, req.Text)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	response.OK(c, http.StatusOK, gin.H{"text": req.Text, "algo": req.Algo, "hash": sum})
}

type identifyRequest struct {
	Hash string `json:"hash"`
}

// IdentifyHash handles POST /api/v1/util/hash-identify
func (h *Handler) IdentifyHash(c *gin.Context) {
	var req identifyRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Hash == "" {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with a 'hash' field.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{
		"hash":           req.Hash,
		"possible_types": service.IdentifyHash(req.Hash),
	})
}

type transformRequest struct {
	Action string `json:"action"` // encode | decode
	Scheme string `json:"scheme"` // base64|base64url|base32|hex|url
	Text   string `json:"text"`
}

// Transform handles POST /api/v1/util/encode
func (h *Handler) Transform(c *gin.Context) {
	var req transformRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with action, scheme, text.")
		return
	}
	out, err := service.Transform(req.Action, req.Scheme, req.Text)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	response.OK(c, http.StatusOK, gin.H{
		"action": req.Action,
		"scheme": req.Scheme,
		"result": out,
	})
}

type jwtRequest struct {
	Token string `json:"token"`
}

// DecodeJWT handles POST /api/v1/util/jwt-decode
func (h *Handler) DecodeJWT(c *gin.Context) {
	var req jwtRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with a 'token' field.")
		return
	}
	res, err := service.DecodeJWT(req.Token)
	if err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	response.OK(c, http.StatusOK, res)
}
