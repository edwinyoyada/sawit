package handler

import (
	"crypto/rsa"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/labstack/echo/v4"

	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt/v5"
)

type ValidationErrorResponse struct {
	Field  string `json:"field"`
	Error  string `json:"error"`
	Expect string `json:"expect"`
}

type jwtClaims struct {
	Id string
	jwt.RegisteredClaims
}

func ValidateToken(token string) (*jwt.Token, error) {
	if token == "" {
		return nil, errors.New("no token")
	}

	t := strings.Split(token, " ")

	cert, err := getPublicKey()
	if err != nil {
		log.Print(err)
		return nil, err
	}

	tkn, err := jwt.ParseWithClaims(t[1], &jwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		return cert, nil
	})

	return tkn, err
}

func (s *Server) GetProfile(c echo.Context) error {
	tok := c.Request().Header.Get("Authorization")

	token, err := ValidateToken(tok)

	if err != nil {
		log.Print(err)
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Invalid token"})
	}

	claims := token.Claims.(*jwtClaims)

	u, err := s.Repository.GetUserInfoById(c.Request().Context(), claims.Id)
	if err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.JSON(http.StatusOK, u)
}

func (s *Server) PatchProfile(c echo.Context) error {
	tok := c.Request().Header.Get("Authorization")

	token, err := ValidateToken(tok)

	if err != nil {
		log.Print(err)
		return c.JSON(http.StatusForbidden, echo.Map{"error": "Invalid token"})
	}

	claims := token.Claims.(*jwtClaims)

	var user repository.UserUpdate

	if err := c.Bind(&user); err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	if err := c.Validate(user); err != nil {
		var ers []ValidationErrorResponse

		for _, err := range err.(validator.ValidationErrors) {
			er := ValidationErrorResponse{
				Field:  err.Field(),
				Error:  err.Tag(),
				Expect: err.Param(),
			}

			ers = append(ers, er)
		}

		return c.JSON(http.StatusBadRequest, echo.Map{"error": ers})
	}

	if err := s.Repository.UpdateUser(c.Request().Context(), claims.Id, user); err != nil {
		if strings.Contains(err.Error(), "unique") {
			return c.JSON(http.StatusConflict, echo.Map{"error": "Phone number is used"})
		}
	}

	return c.JSON(http.StatusOK, claims)
}

func (s *Server) PostLogin(c echo.Context) error {
	var user repository.User

	if err := c.Bind(&user); err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	id, pw, err := s.Repository.GetUserPassword(c.Request().Context(), user.Phone)

	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid phone or password"})
		}

		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	if err = bcrypt.CompareHashAndPassword([]byte(pw), []byte(user.Password)); err != nil {
		log.Print(err)
		return c.JSON(http.StatusBadRequest, echo.Map{"error": "Invalid phone or password"})
	}

	j := &jwtClaims{
		id,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 10)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, j)

	cert, err := getPrivateKey()
	if err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	t, err := token.SignedString(cert)
	if err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func (s *Server) PostRegister(c echo.Context) error {
	var user repository.User

	if err := c.Bind(&user); err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	if err := c.Validate(user); err != nil {
		var ers []ValidationErrorResponse

		switch t := err.(type) {
		default:
			log.Print(t)
			log.Print(err)
			return c.JSON(http.StatusInternalServerError, "Internal Server Error")
		case validator.ValidationErrors:
			for _, err := range err.(validator.ValidationErrors) {
				er := ValidationErrorResponse{
					Field:  err.Field(),
					Error:  err.Tag(),
					Expect: err.Param(),
				}

				ers = append(ers, er)
			}

			log.Print(err)
			return c.JSON(http.StatusBadRequest, echo.Map{"error": ers})
		}
	}

	hp, err := HashPassword(user.Password)

	if err != nil {
		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	user.Password = hp
	id, err := s.Repository.SaveUser(c.Request().Context(), user)

	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			var ers []ValidationErrorResponse

			er := ValidationErrorResponse{
				Field: "phone",
				Error: "duplicated",
			}
			ers = append(ers, er)

			log.Print(err)
			return c.JSON(http.StatusBadRequest, echo.Map{"error": ers})
		}

		log.Print(err)
		return c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.JSON(http.StatusOK, echo.Map{"id": id})
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(bytes), err
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	dir, err := os.Getwd()

	if err != nil {
		return nil, err
	}

	var (
		privateKey     *rsa.PrivateKey
		privateKeyPath = filepath.Join(dir, "/private.pem")
	)

	rawPrivateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	privateKey, err = jwt.ParseRSAPrivateKeyFromPEM(rawPrivateKey)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func getPublicKey() (*rsa.PublicKey, error) {
	dir, err := os.Getwd()

	if err != nil {
		return nil, err
	}

	var (
		publicKey     *rsa.PublicKey
		publicKeyPath = filepath.Join(dir, "/public.pem")
	)

	rawpublicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	publicKey, err = jwt.ParseRSAPublicKeyFromPEM(rawpublicKey)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
