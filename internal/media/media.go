// Package media re-encodes uploaded images and makes thumbnails.
//
// Every image is decoded and encoded again before it is posted. This drops
// EXIF/GPS and other metadata, and turns files that are valid as two formats
// at once (polyglots) into plain images.
package media

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/jpeg"
	"image/png"

	xdraw "golang.org/x/image/draw"
	_ "golang.org/x/image/webp" // decode only; webp uploads become jpeg or png
)

const (
	// ThumbSize is the longest side of a thumbnail in pixels.
	ThumbSize = 250
	maxSide   = 10000
	maxPixels = 40_000_000
	maxFrames = 300
)

// Result is a processed upload.
type Result struct {
	Data   []byte
	Mime   string
	Width  int
	Height int
	Thumb  []byte
}

// ErrTooLarge is returned when the file or its re-encoding exceeds the limit.
var ErrTooLarge = errors.New("image is too large")

// Process validates, re-encodes and thumbnails an uploaded image.
func Process(data []byte, maxBytes int64) (*Result, error) {
	if int64(len(data)) > maxBytes {
		return nil, ErrTooLarge
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("not a supported image (use jpg, png, gif or webp)")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxSide || cfg.Height > maxSide ||
		cfg.Width*cfg.Height > maxPixels {
		return nil, fmt.Errorf("image dimensions %dx%d are not allowed", cfg.Width, cfg.Height)
	}

	var (
		out   bytes.Buffer
		mime  string
		first image.Image
	)
	switch format {
	case "gif":
		g, err := gif.DecodeAll(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gif: %w", err)
		}
		if len(g.Image) == 0 || len(g.Image) > maxFrames {
			return nil, fmt.Errorf("gif must have 1-%d frames", maxFrames)
		}
		if int64(len(g.Image))*int64(cfg.Width*cfg.Height) > 4*maxPixels {
			return nil, errors.New("gif is too large to process")
		}
		clean := &gif.GIF{
			Image: g.Image, Delay: g.Delay, Disposal: g.Disposal,
			LoopCount: g.LoopCount, Config: g.Config, BackgroundIndex: g.BackgroundIndex,
		}
		if err := gif.EncodeAll(&out, clean); err != nil {
			return nil, err
		}
		mime, first = "image/gif", g.Image[0]
	case "jpeg":
		img, err := jpeg.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("jpeg: %w", err)
		}
		if err := jpeg.Encode(&out, img, &jpeg.Options{Quality: 90}); err != nil {
			return nil, err
		}
		mime, first = "image/jpeg", img
	case "png", "webp":
		img, _, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", format, err)
		}
		if format == "webp" && opaque(img) {
			err = jpeg.Encode(&out, img, &jpeg.Options{Quality: 90})
			mime = "image/jpeg"
		} else {
			err = (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, img)
			mime = "image/png"
		}
		if err != nil {
			return nil, err
		}
		first = img
	default:
		return nil, errors.New("not a supported image (use jpg, png, gif or webp)")
	}
	if int64(out.Len()) > maxBytes {
		return nil, ErrTooLarge
	}
	thumb, err := Thumbnail(first)
	if err != nil {
		return nil, err
	}
	b := first.Bounds()
	return &Result{Data: out.Bytes(), Mime: mime, Width: b.Dx(), Height: b.Dy(), Thumb: thumb}, nil
}

func opaque(img image.Image) bool {
	if o, ok := img.(interface{ Opaque() bool }); ok {
		return o.Opaque()
	}
	return false
}

// Thumbnail scales img to fit ThumbSize×ThumbSize (never upscaling),
// flattens transparency onto a light grey and encodes it as JPEG.
func Thumbnail(img image.Image) ([]byte, error) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > ThumbSize || h > ThumbSize {
		if w >= h {
			w, h = ThumbSize, max(1, h*ThumbSize/w)
		} else {
			w, h = max(1, w*ThumbSize/h), ThumbSize
		}
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.RGBA{0xee, 0xee, 0xee, 0xff}), image.Point{}, draw.Src)
	xdraw.ApproxBiLinear.Scale(dst, dst.Bounds(), img, b, xdraw.Over, nil)
	var out bytes.Buffer
	if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 80}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
