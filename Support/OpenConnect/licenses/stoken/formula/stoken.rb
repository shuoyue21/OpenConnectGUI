class Stoken < Formula
  desc "Tokencode generator compatible with RSA SecurID 128-bit (AES)"
  homepage "https://github.com/stoken-dev/stoken"
  url "https://github.com/stoken-dev/stoken/archive/refs/tags/v0.93.tar.gz"
  sha256 "102e2d112b275efcdc20ef438670e4f24f08870b9072a81fda316efcc38aef9c"
  license "LGPL-2.1-or-later"
  revision 2

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool" => :build
  depends_on "pkgconf" => :build
  depends_on "libtomcrypt"

  uses_from_macos "libxml2"

  def install
    system "./autogen.sh"
    system "./configure", "--disable-silent-rules", *std_configure_args
    system "make", "check"
    system "make", "install"
  end

  test do
    system bin/"stoken", "show", "--random"
  end
end
