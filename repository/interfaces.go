// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import "context"

type RepositoryInterface interface {
	GetTestById(ctx context.Context, input GetTestByIdInput) (output GetTestByIdOutput, err error)
	SaveUser(context.Context, User) (string, error)
	GetUserPassword(context.Context, string) (string, string, error)
	GetUserInfoById(context.Context, string) (User, error)
	UpdateUser(context.Context, string, UserUpdate) error
}
