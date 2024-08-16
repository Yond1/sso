package auth

import (
	"context"
	"errors"
	ssov1 "github.com/GolangLessons/protos/gen/go/sso"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sso/internal/services/auth"
	"sso/internal/storage"
)

type Auth interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		appID int,
	) (token string, err error)
	RegisterNewUser(
		ctx context.Context,
		email string,
		password string,
	) (userID int64, err error)
	IsAdmin(
		ctx context.Context,
		userID int64,
	) (bool, error)
}

type serverApi struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverApi{auth: auth})
}

const (
	emptyValueNumber = 0
	emptyValueString = ""
)

func (s *serverApi) Login(
	ctx context.Context,
	req *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {

	if err := validateLogin(req); err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "InvalidArgument")
		}
		return nil, status.Error(codes.Internal, "iternal error")
	}

	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func (s *serverApi) Register(
	ctx context.Context,
	req *ssov1.RegisterRequest,
) (*ssov1.RegisterResponse, error) {

	if err := validateRegister(req); err != nil {
		return nil, err
	}

	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, storage.ErrUserExist) {
			return nil, status.Error(codes.AlreadyExists, "User AlreadyExists")
		}
		return nil, status.Error(codes.Internal, "iternal error")
	}

	return &ssov1.RegisterResponse{
		UserId: userId,
	}, nil
}
func (s *serverApi) IsAdmin(
	ctx context.Context,
	req *ssov1.IsAdminRequest,
) (*ssov1.IsAdminResponse, error) {
	if err := validateIsAdmin(req); err != nil {
		return nil, err
	}
	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}

		return nil, status.Error(codes.Internal, "iternal error")
	}
	return &ssov1.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil

}

func validateLogin(req *ssov1.LoginRequest) error {
	if req.GetEmail() == emptyValueString {
		return status.Error(codes.InvalidArgument, "требуется электронная почта")
	}
	if req.GetPassword() == emptyValueString {
		return status.Error(codes.InvalidArgument, "требуется пароль")
	}
	if req.GetAppId() == emptyValueNumber {
		return status.Error(codes.InvalidArgument, "требуется app_id")
	}

	return nil
}

func validateRegister(req *ssov1.RegisterRequest) error {
	if req.GetEmail() == emptyValueString {
		return status.Error(codes.InvalidArgument, "требуется электронная почта")
	}
	if req.GetPassword() == emptyValueString {
		return status.Error(codes.InvalidArgument, "требуется пароль")
	}

	return nil
}

func validateIsAdmin(req *ssov1.IsAdminRequest) error {
	if req.GetUserId() == emptyValueNumber {
		return status.Error(codes.InvalidArgument, "требуется userID")
	}
	return nil
}
