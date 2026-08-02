package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"pubapi/internal/auth"
	"pubapi/internal/middleware"
	"pubapi/internal/response"
	"pubapi/internal/store"
)

// AccountHandler serves registration, login, and per-user account/key routes.
type AccountHandler struct {
	store *store.Store
	auth  *auth.Service
}

// NewAccountHandler builds the account handler.
func NewAccountHandler(st *store.Store, a *auth.Service) *AccountHandler {
	return &AccountHandler{store: st, auth: a}
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	AcceptTOS bool   `json:"accept_tos"`
}

// Register handles POST /api/v1/auth/register — self-service client signup.
func (h *AccountHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with email, password, accept_tos.")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if !emailRe.MatchString(req.Email) {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Provide a valid email address.")
		return
	}
	if len(req.Password) < 8 {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Password must be at least 8 characters.")
		return
	}
	if !req.AcceptTOS {
		response.Fail(c, http.StatusBadRequest, "tos_required", "You must accept the Terms of Service to register.")
		return
	}
	if _, err := h.store.GetUserByEmail(req.Email); err == nil {
		response.Fail(c, http.StatusConflict, "email_taken", "An account with this email already exists.")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to create account.")
		return
	}
	user, err := h.store.CreateUser(req.Email, hash, "client", true)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to create account.")
		return
	}
	h.issueSession(c, user, http.StatusCreated)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Login handles POST /api/v1/auth/login — email/password → session JWT.
func (h *AccountHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, http.StatusBadRequest, "invalid_input", "Body must be JSON with email and password.")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil || !auth.CheckPassword(user.PasswordHash, req.Password) {
		response.Fail(c, http.StatusUnauthorized, "invalid_credentials", "Incorrect email or password.")
		return
	}
	h.issueSession(c, user, http.StatusOK)
}

func (h *AccountHandler) issueSession(c *gin.Context, user *store.User, status int) {
	token, exp, err := h.auth.IssueJWT(user)
	if err != nil {
		response.Fail(c, http.StatusInternalServerError, "internal_error", "Failed to issue session.")
		return
	}
	response.OK(c, status, gin.H{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": h.auth.TTLSeconds(),
		"expires_at": exp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		"user":       gin.H{"id": user.ID, "email": user.Email, "role": user.Role},
	})
}

// Account handles GET /api/v1/account — the current user's profile.
func (h *AccountHandler) Account(c *gin.Context) {
	id := userID(c)
	user, err := h.store.GetUserByID(id)
	if err != nil {
		response.Fail(c, http.StatusNotFound, "not_found", "Account not found.")
		return
	}
	response.OK(c, http.StatusOK, gin.H{
		"id": user.ID, "email": user.Email, "role": user.Role,
		"accepted_tos": user.AcceptedTOS, "created_at": user.CreatedAt,
	})
}

// userID reads the authenticated user id set by RequireUser/RequireAdmin.
func userID(c *gin.Context) int64 {
	id, _ := strconv.ParseInt(c.GetString(middleware.CtxUserID), 10, 64)
	return id
}
