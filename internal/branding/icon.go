// Package branding draws the application's T-and-tunnel mark at native icon sizes.
package branding

import (
	"image"
	"image/color"
	"math"
)

// Icon uses supersampling to keep the small Explorer icon and large preview crisp.
func Icon(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const samples = 4
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					px := (float64(x) + (float64(sx)+0.5)/samples) * 256 / float64(size)
					py := (float64(y) + (float64(sy)+0.5)/samples) * 256 / float64(size)
					c := pixel(px, py)
					r += float64(c.R) * float64(c.A) / 255
					g += float64(c.G) * float64(c.A) / 255
					b += float64(c.B) * float64(c.A) / 255
					a += float64(c.A)
				}
			}
			if a > 0 {
				img.SetNRGBA(x, y, color.NRGBA{uint8(math.Round(r * 255 / a)), uint8(math.Round(g * 255 / a)), uint8(math.Round(b * 255 / a)), uint8(math.Round(a / (samples * samples)))})
			}
		}
	}
	return img
}

func pixel(x, y float64) color.NRGBA {
	if !rounded(x, y, 12, 12, 244, 244, 52) {
		return color.NRGBA{}
	}
	c := color.NRGBA{uint8(82 - y*0.15), uint8(41 - y*0.075), uint8(125 - y*0.21), 255}
	if !rounded(x, y, 15, 15, 241, 241, 49) {
		c = color.NRGBA{132, 85, 185, 255}
	}
	d := math.Hypot(x-128, y-131)
	if (d >= 84 && d <= 90 || d >= 65 && d <= 69) && (y > 111 || x < 77 || x > 179) {
		c = color.NRGBA{162, 113, 210, 255}
	}
	if rounded(x, y, 77, 72, 179, 102, 6) || rounded(x, y, 113, 92, 143, 185, 5) {
		c = color.NRGBA{250, 247, 255, 255}
	}
	return c
}

func rounded(x, y, left, top, right, bottom, radius float64) bool {
	dx := math.Max(math.Max(left+radius-x, x-(right-radius)), 0)
	dy := math.Max(math.Max(top+radius-y, y-(bottom-radius)), 0)
	return x >= left && x <= right && y >= top && y <= bottom && dx*dx+dy*dy <= radius*radius
}
