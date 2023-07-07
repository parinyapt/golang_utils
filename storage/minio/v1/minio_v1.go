package PTGUstorage

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"

	"github.com/minio/minio-go/v7"
	"github.com/nfnt/resize"
	PTGUhttp "github.com/parinyapt/golang_utils/http/v1"
	"github.com/pkg/errors"
)

type StorageMinioMethod interface {
	UploadImageFromURL(param ParamUploadImageFromURL) (uploadInfo minio.UploadInfo, err error)
}

type storageMinioReceiverArgument struct {
	minioClient *minio.Client
}

func NewStorageMinio(inputClient *minio.Client) *storageMinioReceiverArgument {
	return &storageMinioReceiverArgument{
		minioClient: inputClient,
	}
}

type ParamUploadImageFromURLresizeConfig struct {
	Width  uint
	Height uint
}

type ParamUploadImageFromURL struct {
	StorageBucket           string
	StorageObjectName       string
	StoragePutObjectOptions minio.PutObjectOptions
	ImageURL                string
	ResizeConfig            *ParamUploadImageFromURLresizeConfig
}

func (receiver *storageMinioReceiverArgument) UploadImageFromURL(param ParamUploadImageFromURL) (uploadInfo minio.UploadInfo, err error) {
	response, err := PTGUhttp.HTTPRequest(PTGUhttp.ParamHTTPRequest{
		Type:   PTGUhttp.TypeJSON,
		Method: http.MethodGet,
		URL:    param.ImageURL,
	})
	if err != nil {
		return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Fail to get image from url")
	}

	if response.StatusCode != http.StatusOK {
		return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Fail to get image from url")
	}

	if param.ResizeConfig == nil {
		uploadInfo, err = receiver.minioClient.PutObject(context.Background(), param.StorageBucket, param.StorageObjectName, bytes.NewReader(response.ResponseBody), response.ContentLength, param.StoragePutObjectOptions)
		if err != nil {
			return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Fail to upload image with original size")
		}

		return uploadInfo, nil
	}

	image, _, err := image.Decode(bytes.NewReader(response.ResponseBody))
	if err != nil {
		return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Fail to decode image")
	}
	imageResize := resize.Resize(param.ResizeConfig.Width, param.ResizeConfig.Height, image, resize.Lanczos3)

	var imageComplete bytes.Buffer
	if response.Header.Get("Content-Type") == "image/png" {
		err = png.Encode(&imageComplete, imageResize)
	} else if response.Header.Get("Content-Type") == "image/jpeg" {
		err = jpeg.Encode(&imageComplete, imageResize, nil)
	} else {
		return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Content type not supported")
	}
	if err != nil {
		return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Fail to encode image")
	}

	uploadInfo, err = receiver.minioClient.PutObject(context.Background(), param.StorageBucket, param.StorageObjectName, &imageComplete, int64(imageComplete.Len()), param.StoragePutObjectOptions)
	if err != nil {
		return uploadInfo, errors.Wrap(err, "[Error][PTGUstorage][Minio.UploadImageFromURL()]->Fail to upload image with resize")
	}

	return uploadInfo, nil
}
