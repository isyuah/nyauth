package avatar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/nyasharp/nyauth/internal/config"
)

type S3Store struct {
	client *s3.Client
	bucket string
	prefix string
}

func NewS3Store(ctx context.Context, cfg config.S3MediaConfig) (*S3Store, error) {
	if strings.TrimSpace(cfg.Bucket) == "" || strings.TrimSpace(cfg.Region) == "" {
		return nil, fmt.Errorf("s3 avatar media bucket and region are required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("s3 avatar media credentials are required")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)),
	)
	if err != nil {
		return nil, fmt.Errorf("loading s3 avatar media configuration: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if strings.TrimSpace(cfg.Endpoint) != "" {
			o.BaseEndpoint = aws.String(strings.TrimSpace(cfg.Endpoint))
		}
		o.UsePathStyle = cfg.PathStyle
	})
	return &S3Store{
		client: client,
		bucket: strings.TrimSpace(cfg.Bucket),
		prefix: strings.Trim(strings.TrimSpace(cfg.Prefix), "/"),
	}, nil
}

func (s *S3Store) Backend() StorageBackend { return StorageS3 }

func (s *S3Store) Put(ctx context.Context, key string, contents []byte, contentType string) error {
	fullKey, err := s.key(key)
	if err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(fullKey),
		Body:          bytes.NewReader(contents),
		ContentLength: aws.Int64(int64(len(contents))),
		ContentType:   aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("put avatar media object: %w", err)
	}
	return nil
}

func (s *S3Store) Get(ctx context.Context, key string) (BlobObject, error) {
	fullKey, err := s.key(key)
	if err != nil {
		return BlobObject{}, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "NoSuchKey" || apiErr.ErrorCode() == "NotFound") {
			return BlobObject{}, ErrNotFound
		}
		return BlobObject{}, fmt.Errorf("get avatar media object: %w", err)
	}
	contentType := ContentType
	if out.ContentType != nil && *out.ContentType != "" {
		contentType = *out.ContentType
	}
	return BlobObject{Body: out.Body, Size: aws.ToInt64(out.ContentLength), ContentType: contentType}, nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	fullKey, err := s.key(key)
	if err != nil {
		return err
	}
	_, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(fullKey),
	})
	if err != nil {
		return fmt.Errorf("delete avatar media object: %w", err)
	}
	return nil
}

func (s *S3Store) key(key string) (string, error) {
	key = strings.Trim(strings.TrimSpace(strings.ReplaceAll(key, "\\", "/")), "/")
	if key == "" || strings.Contains(key, "../") || key == ".." || strings.ContainsRune(key, 0) {
		return "", fmt.Errorf("invalid avatar media object key")
	}
	if s.prefix == "" {
		return key, nil
	}
	return s.prefix + "/" + key, nil
}
