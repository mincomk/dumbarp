{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.dumbarpd;
  tomlFormat = pkgs.formats.toml { };

  useFileSecret = cfg.authTokenFile != null;
  placeholder = "@DUMBARPD_AUTH_TOKEN@";

  settings = lib.recursiveUpdate {
    listen = cfg.listen;
    refresh_interval_secs = cfg.refreshIntervalSecs;
    ifaces = cfg.ifaces;
    manage_routing = cfg.manageRouting;
    neigh_refresh_interval_secs = cfg.neighRefreshIntervalSecs;
    dumbarpd_id = cfg.dumbarpdId;
    auth_token =
      if useFileSecret then placeholder else (if cfg.authToken != null then cfg.authToken else "");
  } cfg.extraConfig;

  baseConfigFile = tomlFormat.generate "dumbarpd.toml" settings;

  runtimeConfigPath = "/run/dumbarpd/dumbarpd.toml";
  configPath = if useFileSecret then runtimeConfigPath else "/etc/dumbarpd.toml";

  listenPort =
    let
      parts = lib.splitString ":" cfg.listen;
    in
    lib.toInt (lib.last parts);

  renderConfig = pkgs.writeShellScript "dumbarpd-render-config" ''
    set -eu
    token=$(cat "$CREDENTIALS_DIRECTORY/auth_token")
    # Escape backslashes then double quotes for safe TOML string embedding.
    escaped=$(printf '%s' "$token" \
      | ${pkgs.gnused}/bin/sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
    ${pkgs.gnused}/bin/sed "s|${placeholder}|$escaped|g" \
      ${baseConfigFile} > ${runtimeConfigPath}
    chmod 0640 ${runtimeConfigPath}
  '';
in
{
  options.services.dumbarpd = {
    enable = lib.mkEnableOption "the dumbarpd XDP ARP responder daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default =
        pkgs.dumbarpd
          or (throw "services.dumbarpd: no `dumbarpd` package — set services.dumbarpd.package or add the flake overlay.");
      defaultText = lib.literalExpression "pkgs.dumbarpd";
      description = "The dumbarpd package to use.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:1028";
      description = "Address:port for the REST control API.";
    };

    authToken = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Bearer token required by the REST API. Written into the config file in
        the Nix store — readable by any local user. Prefer {option}`authTokenFile`
        for production. If both are set, {option}`authTokenFile` wins.
      '';
    };

    authTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/dumbarpd-token";
      description = ''
        Path to a file containing the auth token. Loaded via systemd
        {option}`LoadCredential` and substituted into a runtime config in
        {file}`/run/dumbarpd/dumbarpd.toml`. Keeps the token out of the Nix store.
      '';
    };

    refreshIntervalSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "How often to reconcile DHCP leases with XDP attachments.";
    };

    ifaces = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "wan0" ];
      description = "Interfaces to watch for DHCP leases and attach XDP to.";
    };

    manageRouting = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether the daemon should manage source-based routing for leased IPs.";
    };

    neighRefreshIntervalSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = "How often to re-probe and re-pin the gateway's permanent neighbour entry.";
    };

    dumbarpdId = lib.mkOption {
      type = lib.types.ints.between 0 63;
      default = 0;
      example = 7;
      description = ''
        DSCP mode identity for this node, 1–63. Inbound traffic addressed to a
        leased IP is stamped with this value in the DSCP field so that
        {command}`dumbarp-routerd` on the router nodes can steer the flow's
        replies back here. `0` disables DSCP mode.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the TCP port from {option}`listen` in the firewall.";
    };

    extraConfig = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      description = "Extra keys merged into the rendered TOML config.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.ifaces != [ ];
        message = "services.dumbarpd.ifaces must list at least one interface.";
      }
      {
        assertion = (cfg.authToken != null) || (cfg.authTokenFile != null);
        message = "services.dumbarpd: set either `authToken` or `authTokenFile`.";
      }
    ];

    environment.etc = lib.mkIf (!useFileSecret) {
      "dumbarpd.toml".source = baseConfigFile;
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ listenPort ];
    };

    systemd.services.dumbarpd = {
      description = "dumbarp XDP ARP responder daemon";
      documentation = [ "https://github.com/mincomk/dumbarp" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment.RUST_LOG = lib.mkDefault "info";

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/dumbarpd --config ${configPath}";
        Restart = "on-failure";
        RestartSec = "5s";

        # XDP requires unrestricted locked memory for BPF map allocation.
        LimitMEMLOCK = "infinity";

        # Hardening — mirrors debian/dumbarpd.service.
        ProtectHome = true;
        ProtectKernelLogs = true;
        PrivateTmp = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        NoNewPrivileges = true;

        RuntimeDirectory = "dumbarpd";
        RuntimeDirectoryMode = "0750";
      }
      // lib.optionalAttrs useFileSecret {
        LoadCredential = "auth_token:${cfg.authTokenFile}";
        ExecStartPre = "${renderConfig}";
      };
    };
  };
}
