package repository

import (
	"context"
	"log"
)

func (r *Repository) GetTestById(ctx context.Context, input GetTestByIdInput) (output GetTestByIdOutput, err error) {
	err = r.Db.QueryRowContext(ctx, "SELECT name FROM test WHERE id = $1", input.Id).Scan(&output.Name)
	if err != nil {
		return
	}
	return
}

func (r *Repository) SaveUser(ctx context.Context, user User) (string, error) {
	var id string

	sql := "INSERT INTO users (phone, fullname, password) VALUES ($1, $2, $3) RETURNING id"
	err := r.Db.QueryRowContext(ctx, sql, user.Phone, user.FullName, user.Password).Scan(&id)

	if err != nil {
		log.Print(err)
		return "", err
	}

	return id, nil
}

func (r *Repository) GetUserPassword(ctx context.Context, phone string) (string, string, error) {
	var id, pw string

	sql := "SELECT id, password FROM users WHERE phone = $1"
	err := r.Db.QueryRowContext(ctx, sql, phone).Scan(&id, &pw)

	if err != nil {
		log.Print(err)
		return "", "", err
	}

	return id, pw, nil
}

func (r *Repository) GetUserInfoById(ctx context.Context, id string) (User, error) {
	var fn, ph string
	var u User

	sql := "SELECT fullname, phone FROM users WHERE id = $1"
	err := r.Db.QueryRowContext(ctx, sql, id).Scan(&fn, &ph)

	if err != nil {
		log.Print(err)
		return u, err
	}

	u.FullName = fn
	u.Phone = ph

	return u, nil
}

func (r *Repository) UpdateUser(ctx context.Context, id string, user UserUpdate) error {
	sql := `UPDATE users SET phone = COALESCE(NULLIF($1, ''), phone), fullname = COALESCE(NULLIF($2, ''), fullname) WHERE id = $3`
	err := r.Db.QueryRowContext(ctx, sql, user.Phone, user.FullName, id).Err()

	if err != nil {
		log.Print(err)
		return err
	}

	return nil
}
