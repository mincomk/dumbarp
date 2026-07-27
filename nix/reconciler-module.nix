# Shared NixOS module factory for the two poll-and-reconcile services,
# `dumbarp-gateway` and `dumbarp-routerd`. They differ only in the `[dscp]`
# section and the privileges the eBPF datapath needs.
{
  serviceName,
  description,
  dscp ? false,
}:

{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.${serviceName};
  tomlFormat = pkgs.formats.toml { };

  configFileName = "${serviceName}.toml";
  runtimeConfigPath = "/run/${serviceName}/${configFileName}";

  placeholderFor = i: "@DUMBARP_TOKEN_${toString i}@";
  credentialFor = i: "token_${toString i}";

  useFileSecret = lib.any (d: d.authTokenFile != null) cfg.daemons;
  configPath = if useFileSecret then runtimeConfigPath else "/etc/${configFileName}";

  daemonSettings = lib.imap0 (
    i: d:
    {
      inherit (d)
        name
        endpoint
        nexthop
        device
        ;
      auth_token =
        if d.authTokenFile != null then
          placeholderFor i
        else if d.authToken != null then
          d.authToken
        else
          "";
    }
    // d.extraConfig
  ) cfg.daemons;

  settings = lib.recursiveUpdate (
    {
      refresh_interval_secs = cfg.refreshIntervalSecs;
      stale_after_secs = cfg.staleAfterSecs;
      daemons = daemonSettings;
    }
    // lib.optionalAttrs dscp {
      dscp = {
        ifaces = cfg.dscp.ifaces;
        max_flows = cfg.dscp.maxFlows;
      };
    }
  ) cfg.extraConfig;

  baseConfigFile = tomlFormat.generate configFileName settings;

  renderConfig = pkgs.writeShellScript "${serviceName}-render-config" ''
    set -eu
    ${pkgs.coreutils}/bin/install -m 0640 ${baseConfigFile} ${runtimeConfigPath}
    ${lib.concatStrings (
      lib.imap0 (
        i: d:
        lib.optionalString (d.authTokenFile != null) ''
          token=$(cat "$CREDENTIALS_DIRECTORY/${credentialFor i}")
          # Escape backslashes then double quotes for safe TOML string embedding.
          escaped=$(printf '%s' "$token" \
            | ${pkgs.gnused}/bin/sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
          ${pkgs.gnused}/bin/sed -i "s|${placeholderFor i}|$escaped|g" ${runtimeConfigPath}
        ''
      ) cfg.daemons
    )}
  '';

  loadCredentials = lib.concatLists (
    lib.imap0 (
      i: d: lib.optional (d.authTokenFile != null) "${credentialFor i}:${d.authTokenFile}"
    ) cfg.daemons
  );

  daemonType = lib.types.submodule {
    options = {
      name = lib.mkOption {
        type = lib.types.str;
        description = "Identifier for this daemon. Must be unique.";
      };

      endpoint = lib.mkOption {
        type = lib.types.str;
        example = "http://10.0.0.5:1028";
        description = "Base URL of the dumbarpd instance's REST API.";
      };

      authToken = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Bearer token for this daemon's API. Written into the config file in the
          Nix store — readable by any local user. Prefer {option}`authTokenFile`
          for production. If both are set, {option}`authTokenFile` wins.
        '';
      };

      authTokenFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        example = "/run/secrets/dumbarp-homelab-token";
        description = ''
          Path to a file containing this daemon's bearer token. Loaded via systemd
          {option}`LoadCredential` and substituted into a runtime config under
          {file}`/run/${serviceName}/`. Keeps the token out of the Nix store.
        '';
      };

      nexthop = lib.mkOption {
        type = lib.types.str;
        example = "10.0.0.5";
        description = "Next-hop address traffic for this daemon's leased IPs is sent to.";
      };

      device = lib.mkOption {
        type = lib.types.str;
        example = "br0";
        description = "Egress interface for the route to {option}`nexthop`.";
      };

      extraConfig = lib.mkOption {
        type = tomlFormat.type;
        default = { };
        description = "Extra keys merged into this daemon's TOML table.";
      };
    };
  };
in
{
  options.services.${serviceName} = {
    enable = lib.mkEnableOption description;

    package = lib.mkOption {
      type = lib.types.package;
      default =
        pkgs.${serviceName}
          or (throw "services.${serviceName}: no `${serviceName}` package — set services.${serviceName}.package or add the flake overlay.");
      defaultText = lib.literalExpression "pkgs.${serviceName}";
      description = "The ${serviceName} package to use.";
    };

    refreshIntervalSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = "How often to poll each daemon's `/leases` and reconcile routes.";
    };

    staleAfterSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = ''
        Keep serving a daemon's last-known IP set for this long when its `/leases`
        fetch fails, so transient outages don't flap routes. Must be at least
        {option}`refreshIntervalSecs`.
      '';
    };

    daemons = lib.mkOption {
      type = lib.types.listOf daemonType;
      default = [ ];
      description = "The dumbarpd instances this service polls and installs routes for.";
    };

    extraConfig = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      description = "Extra keys merged into the rendered TOML config.";
    };
  }
  // lib.optionalAttrs dscp {
    dscp = {
      ifaces = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "br0"
          "eth1"
        ];
        description = ''
          Every interface the TC ingress program attaches to — both the
          daemon-facing links and the links where reply traffic enters this
          router. The program tells the two roles apart by packet content, so no
          per-interface role is configured here.
        '';
      };

      maxFlows = lib.mkOption {
        type = lib.types.ints.positive;
        default = 65536;
        description = ''
          Size of the eBPF flow table. Fixed at program load time, so raising it
          requires a restart. Raise it on busy routers.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.daemons != [ ];
        message = "services.${serviceName}.daemons must list at least one entry.";
      }
      {
        assertion = cfg.staleAfterSecs >= cfg.refreshIntervalSecs;
        message = "services.${serviceName}.staleAfterSecs must be >= refreshIntervalSecs.";
      }
      {
        assertion = lib.all (d: (d.authToken != null) || (d.authTokenFile != null)) cfg.daemons;
        message = "services.${serviceName}: every daemon needs either `authToken` or `authTokenFile`.";
      }
      {
        assertion =
          let
            names = map (d: d.name) cfg.daemons;
          in
          names == lib.unique names;
        message = "services.${serviceName}.daemons has duplicate `name` values.";
      }
    ]
    ++ lib.optional dscp {
      assertion = cfg.dscp.ifaces != [ ];
      message = "services.${serviceName}.dscp.ifaces must list at least one interface.";
    };

    environment.etc = lib.mkIf (!useFileSecret) {
      "${configFileName}".source = baseConfigFile;
    };

    systemd.services.${serviceName} = {
      inherit description;
      documentation = [ "https://github.com/mincomk/dumbarp" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment.RUST_LOG = lib.mkDefault "info";

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/${serviceName} --config ${configPath}";
        Restart = "on-failure";
        RestartSec = "5s";

        # Hardening — mirrors debian/${serviceName}.service.
        ProtectHome = true;
        ProtectKernelLogs = true;
        PrivateTmp = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        NoNewPrivileges = true;

        RuntimeDirectory = serviceName;
        RuntimeDirectoryMode = "0750";
      }
      // lib.optionalAttrs dscp {
        # The eBPF datapath needs unrestricted locked memory for map allocation.
        LimitMEMLOCK = "infinity";
        AmbientCapabilities = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
        ];
        CapabilityBoundingSet = [
          "CAP_BPF"
          "CAP_NET_ADMIN"
          "CAP_PERFMON"
        ];
      }
      // lib.optionalAttrs (!dscp) {
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
      }
      // lib.optionalAttrs useFileSecret {
        LoadCredential = loadCredentials;
        ExecStartPre = "${renderConfig}";
      };
    };
  };
}
