package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"nasnet-panel/pkg/routeros"
	"nasnet-panel/pkg/sftp"
)

// V2Ray containers are loaded from an image tar the panel downloads itself
// and copies to the router over SFTP, rather than pulled by RouterOS from a
// registry: the panel's own traffic leaves on the foreign link with retries
// and resume, whereas a RouterOS pull goes wherever the router's main table
// points (often a slow tunnel) and restarts from zero on every hiccup.
const (
	// The release URL is formatted with the architecture suffix (amd64,
	// arm64, armv7). The ".sha256" next to it holds the checksum. The tars
	// live in a public repository so the panel can fetch them without a token.
	v2rayImageReleaseURL = "https://github.com/amirhosseinghods/sing-box-slim/releases/download/v1.14.3/sing-box-slim-1.14.3-%s.tar"
	v2rayImageURLEnv     = "NASNET_V2RAY_IMAGE_URL"

	v2rayImageMaxBytes      = 40 << 20
	v2rayImageFetchAttempts = 4
	v2rayImageFetchTimeout  = 5 * time.Minute

	// Free flash a client needs: the tar itself while it is imported, the
	// extracted root filesystem, and headroom RouterOS needs to keep saving
	// its configuration.
	v2rayFlashHeadroomBytes = 10 << 20
)

// v2rayArchSuffix maps RouterOS's architecture-name to the image tar suffix.
func v2rayArchSuffix(arch string) (string, error) {
	switch arch {
	case "arm64":
		return "arm64", nil
	case "arm":
		return "armv7", nil
	case "x86_64":
		return "amd64", nil
	default:
		return "", fmt.Errorf("V2Ray clients are not available for %q routers", arch)
	}
}

func v2rayImageURL(suffix string) string {
	if url := strings.TrimSpace(os.Getenv(v2rayImageURLEnv)); url != "" {
		return strings.ReplaceAll(url, "{arch}", suffix)
	}
	return fmt.Sprintf(v2rayImageReleaseURL, suffix)
}

// progressFunc receives the bytes downloaded so far and the total size (0 when
// the server does not say).
type progressFunc func(done, total int64)

// downloadV2RayImage fetches the image tar, resuming interrupted downloads
// with HTTP ranges, and verifies it against the published sha256.
func downloadV2RayImage(ctx context.Context, url string, progress progressFunc) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, v2rayImageFetchTimeout)
	defer cancel()

	sumRaw, err := httpGetWithRetry(ctx, url+".sha256", 1<<10, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to download image checksum: %w", err)
	}
	fields := strings.Fields(string(sumRaw))
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return nil, errors.New("image checksum file is malformed")
	}
	want := strings.ToLower(fields[0])

	var buf bytes.Buffer
	if _, err := httpGetWithRetry(ctx, url, v2rayImageMaxBytes, &buf, progress); err != nil {
		return nil, fmt.Errorf("failed to download image: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("image checksum mismatch (got %s, want %s)", got, want)
	}
	return buf.Bytes(), nil
}

// httpGetWithRetry downloads url, retrying failed attempts and resuming from
// what was already received when the server honours Range requests. With a
// nil dst the body is returned; otherwise it is written into dst.
func httpGetWithRetry(ctx context.Context, url string, maxBytes int64, dst *bytes.Buffer, progress progressFunc) ([]byte, error) {
	if dst == nil {
		dst = &bytes.Buffer{}
	}
	var lastErr error
	for attempt := 0; attempt < v2rayImageFetchAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 3 * time.Second):
			}
		}
		done, err := httpGetRange(ctx, url, maxBytes, dst, progress)
		if err == nil && done {
			return dst.Bytes(), nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func httpGetRange(ctx context.Context, url string, maxBytes int64, dst *bytes.Buffer, progress progressFunc) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false, err
	}
	offset := int64(dst.Len())
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusPartialContent && offset > 0:
	case resp.StatusCode == http.StatusOK:
		// The server ignored the range (or this is the first attempt):
		// start over.
		dst.Reset()
	default:
		return false, fmt.Errorf("server answered %s", resp.Status)
	}

	remaining := maxBytes - int64(dst.Len())
	body := io.LimitReader(resp.Body, remaining+1)
	if progress != nil {
		total := int64(0)
		if resp.ContentLength >= 0 {
			total = int64(dst.Len()) + resp.ContentLength
		}
		body = &progressReader{r: body, done: int64(dst.Len()), total: total, report: progress}
	}
	n, err := io.Copy(dst, body)
	if int64(dst.Len()) > maxBytes {
		return false, fmt.Errorf("download is larger than %d bytes", maxBytes)
	}
	if err != nil {
		return false, err
	}
	if resp.ContentLength >= 0 && n < resp.ContentLength {
		return false, io.ErrUnexpectedEOF
	}
	return true, nil
}

// progressReader reports how much of a download has arrived.
type progressReader struct {
	r           io.Reader
	done, total int64
	report      progressFunc
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	p.report(p.done, p.total)
	return n, err
}

// v2rayImageUpload copies an image tar onto the router.
type v2rayImageUpload struct {
	sftp sftp.Config
}

// stageV2RayImage downloads the image tar for the router's architecture and
// uploads it under nasnet-panel/container-images. It returns the router path
// to pass as the container's file.
func stageV2RayImage(ctx context.Context, client *routeros.Client, up v2rayImageUpload, name string, progress progressFunc) (string, error) {
	resources, err := client.GetResourceInfo()
	if err != nil {
		return "", fmt.Errorf("failed to read router resources: %w", err)
	}
	suffix, err := v2rayArchSuffix(resources.Architecture)
	if err != nil {
		return "", err
	}

	image, err := downloadV2RayImage(ctx, v2rayImageURL(suffix), progress)
	if err != nil {
		return "", err
	}

	// The extracted root filesystem is about the size of the tar (the
	// sing-box binary is already UPX-compressed), so budget for both.
	need := int64(len(image))*2 + v2rayFlashHeadroomBytes
	if resources.HDDFree < need {
		return "", fmt.Errorf("not enough free storage on the router: %d MB needed, %d MB free",
			need>>20, resources.HDDFree>>20)
	}

	dir := pluginStoragePrefix(client) + routeros.NasnetPanelDir + "/container-images"
	if err := client.EnsureDir(dir); err != nil {
		return "", err
	}
	path := fmt.Sprintf("%s/%s-%s.tar", dir, name, suffix)

	sc := sftp.NewClient(up.sftp)
	if err := sc.Connect(); err != nil {
		return "", fmt.Errorf("failed to connect to the router over SFTP: %w", err)
	}
	defer func() { _ = sc.Close() }()
	if err := sc.UploadFromReader(bytes.NewReader(image), path); err != nil {
		return "", err
	}
	return path, nil
}
