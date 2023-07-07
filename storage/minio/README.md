# PTGU Storage Minio

## Import
```go
import (
  PTGUstorage "github.com/parinyapt/golang_utils/storage/minio/v1"
)
```

## Example
### Config Minio
```go
minioClient, err := minio.New("MINIO_ENDPOINT", &minio.Options{
  Creds:  credentials.NewStaticV4("MINIO_ACCESS_KEY", "MINIO_SECRET_ACCESS_KEY", ""),
  Secure: false,
})
if err != nil {
  panic(err)
}

minioUtils := PTGUstorage.NewStorageMinio(minioClient)
```

## Upload Image From URL with Resize
- StoragePutObjectOptions is optional
- ResizeConfig is optional
- ResizeConfig is required Width and Height if you want to resize image, if not it will upload original image
```go
uploadInfo, err := minioUtils.UploadImageFromURL(PTGUstorage.ParamUploadImageFromURL{
  StorageBucket:     "MINIO_BUCKET",
  StorageObjectName: "MINIO_OBJECT_NAME",
  StoragePutObjectOptions: &minio.PutObjectOptions{
    ContentType: "CONTENT_TYPE",
  },
  ImageURL:          "IMAGE_URL",
  ResizeConfig:      &PTGUstorage.ParamUploadImageFromURLresizeConfig{
    Width: 100, 
    Height: 100,
  },
})

if err != nil {
  panic(err)
}

fmt.Println(uploadInfo)
```