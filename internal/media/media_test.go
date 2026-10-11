package media

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func sampleImage(w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	return img
}

// withEXIF inserts an APP1 Exif segment carrying a fake GPS marker right
// after the JPEG SOI marker.
func withEXIF(t *testing.T, jpg []byte) []byte {
	t.Helper()
	payload := append([]byte("Exif\x00\x00"), []byte("GPSLatitude=41.0082")...)
	seg := []byte{0xFF, 0xE1, byte((len(payload) + 2) >> 8), byte(len(payload) + 2)}
	seg = append(seg, payload...)
	out := append([]byte{}, jpg[:2]...)
	out = append(out, seg...)
	return append(out, jpg[2:]...)
}

func TestJPEGMetadataStripped(t *testing.T) {
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, sampleImage(400, 300), nil); err != nil {
		t.Fatal(err)
	}
	in := withEXIF(t, buf.Bytes())
	if !bytes.Contains(in, []byte("GPSLatitude")) {
		t.Fatal("test setup: EXIF not inserted")
	}
	res, err := Process(in, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(res.Data, []byte("Exif")) || bytes.Contains(res.Data, []byte("GPSLatitude")) {
		t.Fatal("metadata survived re-encoding")
	}
	if res.Mime != "image/jpeg" || res.Width != 400 || res.Height != 300 {
		t.Fatalf("got %s %dx%d", res.Mime, res.Width, res.Height)
	}
	th, err := jpeg.DecodeConfig(bytes.NewReader(res.Thumb))
	if err != nil {
		t.Fatal(err)
	}
	if th.Width != ThumbSize || th.Height != 187 {
		t.Fatalf("thumb %dx%d", th.Width, th.Height)
	}
}

func TestPNGPolyglotTailDropped(t *testing.T) {
	var buf bytes.Buffer
	png.Encode(&buf, sampleImage(10, 10))
	in := append(buf.Bytes(), []byte("<script>alert(1)</script>")...)
	res, err := Process(in, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(res.Data, []byte("<script>")) {
		t.Fatal("trailing payload survived")
	}
}

func TestGIFAnimationKept(t *testing.T) {
	pal := color.Palette{color.Black, color.White}
	g := &gif.GIF{}
	for range 3 {
		g.Image = append(g.Image, image.NewPaletted(image.Rect(0, 0, 8, 8), pal))
		g.Delay = append(g.Delay, 10)
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, g); err != nil {
		t.Fatal(err)
	}
	res, err := Process(buf.Bytes(), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	out, err := gif.DecodeAll(bytes.NewReader(res.Data))
	if err != nil || len(out.Image) != 3 {
		t.Fatalf("frames lost: %v", err)
	}
}

func TestRejects(t *testing.T) {
	if _, err := Process([]byte("not an image"), 1<<20); err == nil {
		t.Fatal("garbage accepted")
	}
	var buf bytes.Buffer
	png.Encode(&buf, sampleImage(10, 10))
	if _, err := Process(buf.Bytes(), 10); err != ErrTooLarge {
		t.Fatalf("size limit: %v", err)
	}
	// A PNG header claiming a huge canvas must be refused before decoding.
	bomb := buf.Bytes()
	bomb = append([]byte{}, bomb...)
	// IHDR width/height live at bytes 16-23.
	copy(bomb[16:24], []byte{0, 0, 0x4e, 0x20, 0, 0, 0x4e, 0x20}) // 20000x20000
	binary.BigEndian.PutUint32(bomb[29:33], crc32.ChecksumIEEE(bomb[12:29]))
	if _, err := Process(bomb, 2<<20); err == nil || !strings.Contains(err.Error(), "dimensions") {
		t.Fatalf("decompression bomb: %v", err)
	}
}
