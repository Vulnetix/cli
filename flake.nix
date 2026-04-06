{
  description = "Vulnetix CLI for vulnerability management";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
<<<<<<< HEAD
        version = "1.27.0";
=======
        version = "1.27.0";
>>>>>>> 5b061d80679c748e0fee1ba1cc3a93962bea1c86
      in
      {
        packages = {
          vulnetix = pkgs.buildGoModule {
            pname = "vulnetix";
            inherit version;
            src = ./.;

            # To update: run `nix build` — the error message will show the correct hash.
            vendorHash = pkgs.lib.fakeHash;

            ldflags = [
              "-s"
              "-w"
              "-X github.com/vulnetix/cli/cmd.version=${version}"
              "-X github.com/vulnetix/cli/cmd.commit=${self.shortRev or "dirty"}"
              "-X github.com/vulnetix/cli/cmd.buildDate=1970-01-01T00:00:00Z"
            ];

            postInstall = ''
              mv $out/bin/cli $out/bin/vulnetix
            '';

            meta = with pkgs.lib; {
              description = "Vulnetix CLI for vulnerability management";
              homepage = "https://github.com/Vulnetix/cli";
              license = licenses.mit;
              mainProgram = "vulnetix";
            };
          };

          default = self.packages.${system}.vulnetix;
        };

        apps = {
          vulnetix = flake-utils.lib.mkApp {
            drv = self.packages.${system}.vulnetix;
          };
          default = self.apps.${system}.vulnetix;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
            gopls
            gotools
          ];
        };
      }
    );
}
