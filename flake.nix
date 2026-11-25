{
  description = "kpxc-mcp: KeePassXC logins and tokens for agents, without the agent seeing them";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: {
        default = pkgs.python3Packages.buildPythonApplication {
          pname = "kpxc-mcp";
          version = "0.1.0";
          pyproject = true;
          src = ./.;
          build-system = [ pkgs.python3Packages.setuptools ];
          dependencies = with pkgs.python3Packages; [ pynacl websockets ];
          # the tests resolve commands through the system PATH and drive a browser: run them in the devShell
          doCheck = false;
          makeWrapperArgs = [ "--prefix" "PATH" ":" "${pkgs.zenity}/bin" ];
          meta.mainProgram = "kpxc-mcp";
        };
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [ ps.pynacl ps.websockets ps.pytest ]))
            pkgs.zenity
          ];
        };
      });
    };
}
