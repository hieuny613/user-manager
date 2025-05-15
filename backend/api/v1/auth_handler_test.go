package v1_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"backend/api/v1"
	"backend/model"
	"backend/service"
	"backend/service/mocks"
)

func TestAuthHandler_Login(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create mock service
	mockAuthService := new(mocks.MockAuthService)

	// Create test logger
	logger := logrus.New()
	logger.SetOutput(bytes.NewBuffer(nil)) // Discard logs in tests

	// Create handler with mock service
	handler := v1.NewAuthHandler(mockAuthService, logger)

	// Create test router
	router := gin.New()
	router.POST("/login", handler.Login)

	// Test cases
	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "Valid login",
			requestBody: service.LoginRequest{
				Email:    "test@example.com",
				Password: "Password123!",
			},
			mockSetup: func() {
				userID := uuid.New()
				sessionID := uuid.New()
				user := &model.User{
					ID:       userID,
					Email:    "test@example.com",
					Username: "testuser",
				}
				tokenResponse := service.TokenResponse{
					AccessToken:  "access_token",
					RefreshToken: "refresh_token",
					ExpiresAt:    time.Now().Add(15 * time.Minute),
					TokenType:    "Bearer",
				}

				mockAuthService.On("Login", mock.Anything, mock.MatchedBy(func(req service.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "Password123!"
				}), mock.Anything, mock.Anything).Return(tokenResponse, user, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"access_token":  "access_token",
				"refresh_token": "refresh_token",
				"token_type":    "Bearer",
			},
		},
		{
			name: "Invalid credentials",
			requestBody: service.LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword",
			},
			mockSetup: func() {
				mockAuthService.On("Login", mock.Anything, mock.MatchedBy(func(req service.LoginRequest) bool {
					return req.Email == "test@example.com" && req.Password == "WrongPassword"
				}), mock.Anything, mock.Anything).Return(service.TokenResponse{}, nil, errors.New("invalid credentials"))
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"error": "invalid credentials",
			},
		},
		{
			name:        "Invalid request",
			requestBody: "invalid json",
			mockSetup: func() {
				// No mock setup needed for invalid request
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": mock.Anything, // We just check that there's an error message
			},
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock expectations
			tc.mockSetup()

			// Create request
			var reqBody []byte
			var err error
			if s, ok := tc.requestBody.(string); ok {
				reqBody = []byte(s)
			} else {
				reqBody, err = json.Marshal(tc.requestBody)
				assert.NoError(t, err)
			}

			req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(reqBody))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rec := httptest.NewRecorder()

			// Serve request
			router.ServeHTTP(rec, req)

			// Check response
			assert.Equal(t, tc.expectedStatus, rec.Code)

			// Parse response body
			var respBody map[string]interface{}
			err = json.Unmarshal(rec.Body.Bytes(), &respBody)
			assert.NoError(t, err)

			// Check response body
			for k, v := range tc.expectedBody {
				if v == mock.Anything {
					// Just check that the key exists
					_, exists := respBody[k]
					assert.True(t, exists, "Expected key %s to exist in response", k)
				} else {
					assert.Equal(t, v, respBody[k], "Expected %s to be %v, got %v", k, v, respBody[k])
				}
			}

			// Verify mock expectations
			mockAuthService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_Register(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)

	// Create mock service
	mockAuthService := new(mocks.MockAuthService)

	// Create test logger
	logger := logrus.New()
	logger.SetOutput(bytes.NewBuffer(nil)) // Discard logs in tests

	// Create handler with mock service
	handler := v1.NewAuthHandler(mockAuthService, logger)

	// Create test router
	router := gin.New()
	router.POST("/register", handler.Register)

	// Test cases
	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "Valid registration",
			requestBody: service.RegisterRequest{
				Email:     "test@example.com",
				Username:  "testuser",
				Password:  "Password123!",
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func() {
				userID := uuid.New()
				user := &model.User{
					ID:              userID,
					Email:           "test@example.com",
					Username:        "testuser",
					FirstName:       "Test",
					LastName:        "User",
					IsActive:        true,
					IsEmailVerified: false,
					CreatedAt:       time.Now(),
					UpdatedAt:       time.Now(),
				}

				mockAuthService.On("Register", mock.Anything, mock.MatchedBy(func(req service.RegisterRequest) bool {
					return req.Email == "test@example.com" && req.Username == "testuser"
				}), mock.Anything, mock.Anything).Return(user, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody: map[string]interface{}{
				"email":            "test@example.com",
				"username":         "testuser",
				"first_name":       "Test",
				"last_name":        "User",
				"is_active":        true,
				"is_email_verified": false,
			},
		},
		{
			name: "Email already exists",
			requestBody: service.RegisterRequest{
				Email:     "existing@example.com",
				Username:  "newuser",
				Password:  "Password123!",
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func() {
				mockAuthService.On("Register", mock.Anything, mock.MatchedBy(func(req service.RegisterRequest) bool {
					return req.Email == "existing@example.com"
				}), mock.Anything, mock.Anything).Return(nil, errors.New("email already exists"))
			},
			expectedStatus: http.StatusConflict,
			expectedBody: map[string]interface{}{
				"error": "email already exists",
			},
		},
		{
			name: "Username already exists",
			requestBody: service.RegisterRequest{
				Email:     "new@example.com",
				Username:  "existinguser",
				Password:  "Password123!",
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func() {
				mockAuthService.On("Register", mock.Anything, mock.MatchedBy(func(req service.RegisterRequest) bool {
					return req.Username == "existinguser"
				}), mock.Anything, mock.Anything).Return(nil, errors.New("username already exists"))
			},
			expectedStatus: http.StatusConflict,
			expectedBody: map[string]interface{}{
				"error": "username already exists",
			},
		},
		{
			name: "Invalid password",
			requestBody: service.RegisterRequest{
				Email:     "test@example.com",
				Username:  "testuser",
				Password:  "weak",
				FirstName: "Test",
				LastName:  "User",
			},
			mockSetup: func() {
				mockAuthService.On("Register", mock.Anything, mock.MatchedBy(func(req service.RegisterRequest) bool {
					return req.Password == "weak"
				}), mock.Anything, mock.Anything).Return(nil, errors.New("password must be at least 8 characters long"))
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "password must be at least 8 characters long",
			},
		},
		{
			name:        "Invalid request",
			requestBody: "invalid json",
			mockSetup: func() {
				// No mock setup needed for invalid request
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": mock.Anything, // We just check that there's an error message
			},
		},
	}

	// Run tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock expectations
			tc.mockSetup()

			// Create request
			var reqBody []byte
			var err error
			if s, ok := tc.requestBody.(string); ok {
				reqBody = []byte(s)
			} else {
				reqBody, err = json.Marshal(tc.requestBody)
				assert.NoError(t, err)
			}

			req, err := http.NewRequest("POST", "/register", bytes.NewBuffer(reqBody))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			rec := httptest.NewRecorder()

			// Serve request
			router.ServeHTTP(rec, req)

			// Check response
			assert.Equal(t, tc.expectedStatus, rec.Code)

			// Parse response body
			var respBody map[string]interface{}
			err = json.Unmarshal(rec.Body.Bytes(), &respBody)
			assert.NoError(t, err)

			// Check response body
			for k, v := range tc.expectedBody {
				if v == mock.Anything {
					// Just check that the key exists
					_, exists := respBody[k]
					assert.True(t, exists, "Expected key %s to exist in response", k)
				} else {
					assert.Equal(t, v, respBody[k], "Expected %s to be %v, got %v", k, v, respBody[k])
				}
			}

			// Verify mock expectations
			mockAuthService.AssertExpectations(t)
		})
	}
}

// Additional test functions for other auth handler methods would follow the same pattern