"""
SwitchGate - Holographic Cyber App Icon & MSIX Asset Generator
"""
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

BASE_DIR = Path(__file__).resolve().parent
ASSETS_DIR = BASE_DIR / "assets"
ASSETS_DIR.mkdir(exist_ok=True)

def generate_cyber_icon(size: int) -> Image.Image:
    """Generates a high-res glowing cyan & emerald holographic cyber I/O shield icon."""
    img = Image.new("RGBA", (size, size), color=(0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Gradient-like background rounded rect
    margin = max(2, int(size * 0.05))
    radius = int(size * 0.22)
    
    # Outer Glow Layer
    glow_box = [margin, margin, size - margin, size - margin]
    draw.rounded_rectangle(glow_box, radius=radius, fill=(10, 14, 26, 255), outline=(0, 245, 255, 220), width=max(1, int(size * 0.04)))
    
    # Inner Cyber Ring
    inner_margin = int(size * 0.16)
    inner_box = [inner_margin, inner_margin, size - inner_margin, size - inner_margin]
    draw.ellipse(inner_box, outline=(0, 255, 157, 180), width=max(1, int(size * 0.03)))
    
    # Center I/O Symbol
    core_margin = int(size * 0.28)
    core_box = [core_margin, core_margin, size - core_margin, size - core_margin]
    draw.ellipse(core_box, fill=(0, 245, 255, 230))

    # Center vertical notch
    bar_w = max(2, int(size * 0.08))
    bar_h = int(size * 0.24)
    bar_x = (size - bar_w) // 2
    bar_y = int(size * 0.26)
    draw.rounded_rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + bar_h], radius=bar_w//2, fill=(8, 12, 22, 255))

    return img

def main():
    print("[*] Generating high-resolution SwitchGate brand icons and MSIX assets...")
    
    # Master Logo 512x512
    master_512 = generate_cyber_icon(512)
    master_512.save(ASSETS_DIR / "logo.png", "PNG")
    master_512.save(BASE_DIR / "frontend" / "img" / "logo.png", "PNG") if (BASE_DIR / "frontend" / "img").exists() else None

    # Windows Multi-Res ICO
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    ico_imgs = [generate_cyber_icon(s[0]) for s in ico_sizes]
    ico_imgs[0].save(
        ASSETS_DIR / "icon.ico",
        format="ICO",
        sizes=ico_sizes,
        append_images=ico_imgs[1:]
    )

    # MSIX / Windows Store Manifest Assets
    msix_assets = {
        "Square44x44Logo.png": (44, 44),
        "Square150x150Logo.png": (150, 150),
        "Square310x310Logo.png": (310, 310),
        "StoreLogo.png": (50, 50),
        "SplashScreen.png": (620, 300),
        "Wide310x150Logo.png": (310, 150),
    }

    for name, (w, h) in msix_assets.items():
        if w == h:
            asset_img = generate_cyber_icon(w)
        else:
            # Wide / Splash
            asset_img = Image.new("RGBA", (w, h), color=(8, 11, 19, 255))
            logo_icon = generate_cyber_icon(int(h * 0.65))
            offset_x = (w - logo_icon.width) // 2
            offset_y = (h - logo_icon.height) // 2
            asset_img.paste(logo_icon, (offset_x, offset_y), logo_icon)

        asset_img.save(ASSETS_DIR / name, "PNG")

    print("[✅] All brand logos, Windows .ICO, and MSIX visual assets generated successfully!")

if __name__ == "__main__":
    main()
