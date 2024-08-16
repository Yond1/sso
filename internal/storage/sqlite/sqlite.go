package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	_ "github.com/mattn/go-sqlite3"
	"sso/internal/domain/model"
	"sso/internal/storage"
)

type Storage struct {
	db *sql.DB
}

func New(storagePath string) (*Storage, error) {
	const op = "storage.sqlite.New"

	db, err := sql.Open("sqlite3", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &Storage{db: db}, nil
}

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.sqlite.SaveUser"

	// Простенький зпрос на добавление пользователя
	stmt, err := s.db.Prepare("INSERT INTO users(email, pass_hash) VALUES(?, ?)")
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	// Выполняем запрос, передав параметры
	res, err := stmt.ExecContext(ctx, email, passHash)
	if err != nil {
		var sqliteErr sqlite3.Error

		// Небольшое кунг-фу для выявления ошибки ErrConstraintUnique
		// (см. подробности ниже)
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return 0, fmt.Errorf("%s: %w", op, storage.ErrUserExist)
		}

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	// Получаем ID созданной записи
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

// GetUser returns user by email.
func (s *Storage) GetUser(ctx context.Context, email string) (model.User, error) {
	const op = "storage.sqlite.GetUser"

	stmt, err := s.db.Prepare("SELECT id, email, pass_hash FROM users WHERE email = ?")
	if err != nil {
		return model.User{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, email)

	var user model.User
	err = row.Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.User{}, fmt.Errorf("%s: %w", op, storage.ErrUserNotFound)
		}
		return model.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil

}

// IsAdmin checked user is admin by userID
func (s *Storage) IsAdmin(ctx context.Context, userId int64) (bool, error) {
	const op = "storage.sqlite.IsAdmin"

	stmt, err := s.db.Prepare("SELECT is_admin FROM users WHERE id = ?")
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, userId)

	var isAdmin bool
	err = row.Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil

}

// App Get APP ID
func (s *Storage) App(ctx context.Context, appID int) (model.App, error) {
	const op = "storage.sqlite.App"

	stmt, err := s.db.Prepare("SELECT id, name, secret FROM apps WHERE id = ?")
	if err != nil {
		return model.App{}, fmt.Errorf("%s: %w", op, err)
	}

	row := stmt.QueryRowContext(ctx, appID)

	var app model.App
	err = row.Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.App{}, fmt.Errorf("%s: %w", op, storage.ErrAppNotFound)
		}
		return model.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
