#!/bin/python3

#below line imports the Image module and ImageChops module from the PIL (Pillow) library.
from PIL import Image, ImageChops

#opening lemur.png and flag.png and store them in img1 and img2
img1 = Image.open('lemur.png')
img2 = Image.open('flag.png')

#below line Computes the absolute difference between img1 and img2 pixel by pixel and
#display the resulting image using system's default image viewer
ImageChops.difference(img1, img2).show()
