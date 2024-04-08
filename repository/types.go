// This file contains types that are used in the repository layer.
package repository

type GetTestByIdInput struct {
	Id string
}

type GetTestByIdOutput struct {
	Name string
}

type User struct {
	FullName string `json:"fullname" validate:"required,min=3,max=60"`
	Phone    string `json:"phone" validate:"required,startswith=+62,min=10,max=13"`
	Password string `json:"password,omitempty" validate:"required,min=6,max=64,validatepassword"`
}

type UserUpdate struct {
	FullName string `json:"fullname" validate:"required,min=3,max=60"`
	Phone    string `json:"phone" validate:"required,startswith=+62,min=10,max=13"`
}
