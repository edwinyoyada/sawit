package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/go-playground/validator/v10"
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

func TestHello(t *testing.T) {

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
}

func TestPostLogin(t *testing.T) {
	t.Run("should return bad request", func(t *testing.T) {
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
}

func TestHashPassword(t *testing.T) {
	t.Run("should not be empty", func(t *testing.T) {
		pass, err := HashPassword("asdf")

		assert.NotEmpty(t, pass)
		assert.Empty(t, err)

	})
}

func TestGetProfile(t *testing.T) {
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
}

func TestPatchProfile(t *testing.T) {
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
