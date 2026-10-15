package internal

type hf_ModelDownloaderFactoryInterface interface {
	Download(name string) error
}
