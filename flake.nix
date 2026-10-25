{
  description = "Netgap — LAN security scanner";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      # The workspace version is the single place a source build reads it
      # from; release tags carry the same number until the release workflow
      # stamps a binary with its own.
      version = (nixpkgs.lib.importTOML ./Cargo.toml).workspace.package.version;
    in
    {
      packages = forAllSystems (pkgs:
        let
          netgap = pkgs.rustPlatform.buildRustPackage {
            pname = "netgap";
            inherit version;

            # The checkout is the source; a flake copied out of a tag builds
            # the tree that tag names.
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [
              "--bin"
              "netgap"
              "--bin"
              "netgap-gui"
            ];

            nativeBuildInputs = [ pkgs.makeWrapper ];

            # The window opens its graphics and input libraries when it
            # starts, which on NixOS means naming them: a bare dlopen finds
            # nothing on a system with no /usr/lib.
            postInstall = ''
              install -Dm644 netgap-gui/assets/netgap.desktop \
                $out/share/applications/netgap.desktop
              install -Dm644 netgap-gui/assets/netgap.svg \
                $out/share/icons/hicolor/scalable/apps/netgap.svg
              wrapProgram $out/bin/netgap-gui \
                --prefix LD_LIBRARY_PATH : ${
                  pkgs.lib.makeLibraryPath [
                    pkgs.fontconfig
                    pkgs.libglvnd
                    pkgs.libx11
                    pkgs.libxcursor
                    pkgs.libxi
                    pkgs.libxkbcommon
                    pkgs.libxrandr
                    pkgs.wayland
                  ]
                }
            '';

            meta = {
              description = "LAN security scanner: the command line and the window application";
              homepage = "https://github.com/fuunshi/netgap";
              license = with nixpkgs.lib.licenses; [
                mit
                asl20
              ];
              platforms = nixpkgs.lib.platforms.linux;
              mainProgram = "netgap";
            };
          };
        in
        {
          inherit netgap;
          default = netgap;
        });
    };
}
