{ pkgs ? import ./nixpkgs.nix {} }:

with pkgs;

let
in
{
  py313 = stdenv.mkDerivation rec {
    name = "python313-with-pytest";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python313Full
      poetry
    ];
  };

  py312 = stdenv.mkDerivation rec {
    name = "python312-with-pytest";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python312Full
      poetry
    ];
  };
 
  py311 = stdenv.mkDerivation rec {
    name = "python311-with-pytest";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python311Full
      poetry
    ];
  };

  py310 = stdenv.mkDerivation rec {
    name = "python310-with-pytest";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python310Full
      poetry
    ];
  };

  py39 = stdenv.mkDerivation rec {
    name = "python39-with-pytest";

    buildInputs = [
      cacert
      git
      gnumake
      openssh
      python39Full
      poetry
    ];
  };
}
