package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

type CustomValidator struct {
	validator *validator.Validate
}

func (c *CustomValidator) Validate(i interface{}) error {
	if err := c.validator.Struct(i); err != nil {
		return err
	}
	return nil
}

func ValidatePassword(fl validator.FieldLevel) bool {
	var number, upper, special bool

	for _, c := range fl.Field().String() {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		}
	}

	return number && upper && special
}

func TestPostRegister(t *testing.T) {
	t.Run("should pass", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"fullname":"edwin yo", "phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/register")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().SaveUser(c.Request().Context(), gomock.Any()).AnyTimes()

		h.PostRegister(c)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("should return internal server error", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"fullname":"edwin yo", "phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/register")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().SaveUser(c.Request().Context(), gomock.Any()).AnyTimes()

		h.PostRegister(c)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("should return 400", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/register")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().SaveUser(c.Request().Context(), gomock.Any()).AnyTimes()

		h.PostRegister(c)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("should return 400 - duplicated", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"fullname":"edwin yo", "phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/register")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().SaveUser(c.Request().Context(), gomock.Any()).Return("", errors.New("unique")).AnyTimes()

		h.PostRegister(c)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("should return 500 - other error", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"fullname":"edwin yo", "phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/register")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().SaveUser(c.Request().Context(), gomock.Any()).Return("", errors.New("other error")).AnyTimes()

		h.PostRegister(c)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestPostLogin(t *testing.T) {
	t.Run("should be success", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/login")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserPassword(c.Request().Context(), gomock.Any()).Return("1", "$2a$12$CgBNArPeo1.i.hcvTKk.5.pZTfzEndusEviHGKbwfZ.XjL3XHW3ou", nil).AnyTimes()

		h.PostLogin(c)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
	t.Run("should return internal server error", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/login")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserPassword(c.Request().Context(), gomock.Any()).Return("1", "$2a$12$CgBNArPeo1.i.hcvTKk.5.pZTfzEndusEviHGKbwfZ.XjL3XHW3ou", nil).AnyTimes()

		h.PostLogin(c)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("should return bad request - invalid password", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/login")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserPassword(c.Request().Context(), gomock.Any()).AnyTimes()

		h.PostLogin(c)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("should return bad request - no rows", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/login")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserPassword(c.Request().Context(), gomock.Any()).Return("", "", errors.New("no rows")).AnyTimes()

		h.PostLogin(c)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("should return bad request - internal server error", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)

		userJSON := `{"phone": "+6281232123", "password": "Asdf1234!"}`

		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(userJSON))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/login")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserPassword(c.Request().Context(), gomock.Any()).Return("", "", errors.New("some error")).AnyTimes()

		h.PostLogin(c)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("should not be empty", func(t *testing.T) {
		pass, err := HashPassword("asdf")

		assert.NotEmpty(t, pass)
		assert.Empty(t, err)

	})
}

func TestGetProfile(t *testing.T) {
	t.Run("should be success", func(t *testing.T) {
		j := &jwtClaims{
			"1",
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

		cert, err := getPrivateKey()
		if err != nil {
			log.Print(err)
		}

		tkn, err := token.SignedString(cert)
		if err != nil {
			log.Print(err)
		}

		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", fmt.Sprintf("%s%s", "Bearer ", tkn))

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		u := repository.User{
			FullName: "test",
			Phone:    "+628123123",
		}

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).Return(u, nil).AnyTimes()

		h.GetProfile(c)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("should return forbidden", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).AnyTimes()

		h.GetProfile(c)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("should return internal server error", func(t *testing.T) {
		j := &jwtClaims{
			"1",
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

		cert, err := getPrivateKey()
		if err != nil {
			log.Print(err)
		}

		tkn, err := token.SignedString(cert)
		if err != nil {
			log.Print(err)
		}

		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", fmt.Sprintf("%s%s", "Bearer ", tkn))

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		u := repository.User{}

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).Return(u, errors.New("some error")).AnyTimes()

		h.GetProfile(c)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestPatchProfile(t *testing.T) {

	t.Run("should be success", func(t *testing.T) {
		j := &jwtClaims{
			"1",
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

		cert, err := getPrivateKey()
		if err != nil {
			log.Print(err)
		}

		tkn, err := token.SignedString(cert)
		if err != nil {
			log.Print(err)
		}
		userJSON := `{"fullname": "test", "phone": "+628123123"}`

		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(userJSON))
		req.Header.Set("Authorization", fmt.Sprintf("%s%s", "Bearer ", tkn))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		u := repository.User{
			FullName: "test",
			Phone:    "+628123123",
		}

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).Return(u, nil).AnyTimes()
		repo.EXPECT().UpdateUser(c.Request().Context(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		h.PatchProfile(c)

		log.Print(rec.Body)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("should be success", func(t *testing.T) {
		j := &jwtClaims{
			"1",
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

		cert, err := getPrivateKey()
		if err != nil {
			log.Print(err)
		}

		tkn, err := token.SignedString(cert)
		if err != nil {
			log.Print(err)
		}
		userJSON := `{"fullname": "", "phone": "+628123123"}`

		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(userJSON))
		req.Header.Set("Authorization", fmt.Sprintf("%s%s", "Bearer ", tkn))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		u := repository.User{
			FullName: "test",
			Phone:    "+628123123",
		}

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).Return(u, nil).AnyTimes()
		repo.EXPECT().UpdateUser(c.Request().Context(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

		h.PatchProfile(c)

		log.Print(rec.Body)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("should return conflict", func(t *testing.T) {
		j := &jwtClaims{
			"1",
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

		cert, err := getPrivateKey()
		if err != nil {
			log.Print(err)
		}

		tkn, err := token.SignedString(cert)
		if err != nil {
			log.Print(err)
		}
		userJSON := `{"fullname": "test", "phone": "+628123123"}`

		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(userJSON))
		req.Header.Set("Authorization", fmt.Sprintf("%s%s", "Bearer ", tkn))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		u := repository.User{
			FullName: "test",
			Phone:    "+628123123",
		}

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).Return(u, nil).AnyTimes()
		repo.EXPECT().UpdateUser(c.Request().Context(), gomock.Any(), gomock.Any()).Return(errors.New("unique")).AnyTimes()

		h.PatchProfile(c)

		log.Print(rec.Body)

		assert.Equal(t, http.StatusConflict, rec.Code)
	})

	t.Run("should be internal server error", func(t *testing.T) {
		j := &jwtClaims{
			"1",
			jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

		cert, err := getPrivateKey()
		if err != nil {
			log.Print(err)
		}

		tkn, err := token.SignedString(cert)
		if err != nil {
			log.Print(err)
		}
		userJSON := `{"phone": "+6281232123", "password": "Asdf1234!"}`

		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(userJSON))
		req.Header.Set("Authorization", fmt.Sprintf("%s%s", "Bearer ", tkn))

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		u := repository.User{
			FullName: "test",
			Phone:    "+628123123",
		}

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).Return(u, nil).AnyTimes()

		h.PatchProfile(c)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("should return forbidden", func(t *testing.T) {
		mockCtl := gomock.NewController(t)

		e := echo.New()
		v := validator.New()

		v.RegisterValidation("validatepassword", ValidatePassword)
		e.Validator = &CustomValidator{validator: v}
		req := httptest.NewRequest(http.MethodPatch, "/", nil)

		rec := httptest.NewRecorder()

		c := e.NewContext(req, rec)
		c.SetPath("/profile")

		repo := repository.NewMockRepositoryInterface(mockCtl)

		opts := NewServerOptions{
			Repository: repo,
		}
		h := NewServer(opts)

		repo.EXPECT().GetUserInfoById(c.Request().Context(), gomock.Any()).AnyTimes()

		h.PatchProfile(c)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestRetrieveKeys(t *testing.T) {
	t.Run("should get private key", func(t *testing.T) {
		p, err := getPrivateKey()

		if err != nil {
			log.Println(err)
		}

		assert.NotEmpty(t, p)
	})
	t.Run("should get public key", func(t *testing.T) {
		p, err := getPublicKey()

		if err != nil {
			log.Println(err)
		}

		assert.NotEmpty(t, p)
	})
}
