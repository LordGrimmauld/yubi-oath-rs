{
  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    nix-github-actions = {
      url = "github:nix-community/nix-github-actions";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      self,
      nix-github-actions,
      rust-overlay,
      treefmt-nix,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
      genPkgs =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
      forAllPkgs = f: forAllSystems (system: f (genPkgs system));
      treefmtEval = forAllPkgs (pkgs: treefmt-nix.lib.evalModule pkgs ./treefmt.nix);
    in
    {
      devShells = forAllPkgs (pkgs: {
        default =
          let
            rust = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          in
          pkgs.mkShell {
            nativeBuildInputs = [
            ];
            buildInputs = with pkgs; [
              pkg-config
              pcsclite.dev
              openssl.dev
              rust
            ];
          };
      });

      packages = forAllPkgs (pkgs: {
        # default = ;
      });

      formatter = forAllSystems (system: treefmtEval.${system}.config.build.wrapper);

      checks = forAllSystems (system: {
        formatting = treefmtEval.${system}.config.build.check self;
      });

      githubActions = nix-github-actions.lib.mkGithubMatrix {
        checks = nixpkgs.lib.getAttrs [ "x86_64-linux" ] self.checks;
      }; # todo: figure out testing on aarch64-linux
    };
}
