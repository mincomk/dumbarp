# Shared NixOS module factory for the two poll-and-reconcile services.
#
#   variant = "gateway"  → polls daemons, optionally serves /daemons over HTTP
#   variant = "routerd"  → installs routes plus the DSCP eBPF datapath, and
#                          takes its daemon list either from a gateway or directly
{
  serviceName,
  description,
  variant,
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

  isRouterd = variant == "routerd";
  isGateway = variant == "gateway";

  configFileName = "${serviceName}.toml";
  runtimeConfigPath = "/run/${serviceName}/${configFileName}";

  # Every secret that must be substituted at start-up, from all sources.
  daemonSecrets = lib.concatLists (
    lib.imap0 (
      i: d:
      lib.optional (d.authTokenFile != null) {
        id = "token_${toString i}";
        placeholder = "@DUMBARP_TOKEN_${toString i}@";
        file = d.authTokenFile;
      }
    ) cfg.daemons
  );

  serveSecret = lib.optional (isGateway && cfg.serve != null && cfg.serve.authTokenFile != null) {
    id = "serve_token";
    placeholder = "@DUMBARP_SERVE_TOKEN@";
    file = cfg.serve.authTokenFile;
  };

  upstreamSecret =
    lib.optional (isRouterd && cfg.gateway != null && cfg.gateway.authTokenFile != null)
      {
        id = "gateway_token";
        placeholder = "@DUMBARP_GATEWAY_TOKEN@";
        file = cfg.gateway.authTokenFile;
      };

  secrets = daemonSecrets ++ serveSecret ++ upstreamSecret;
  useFileSecret = secrets != [ ];
  configPath = if useFileSecret then runtimeConfigPath else "/etc/${configFileName}";

  tokenValue =
    placeholder: attrs:
    if attrs.authTokenFile != null then
      placeholder
    else if attrs.authToken != null then
      attrs.authToken
    else
      "";

  daemonSettings = lib.imap0 (
    i: d:
    {
      inherit (d)
        name
        endpoint
        nexthop
        device
        ;
      auth_token = tokenValue "@DUMBARP_TOKEN_${toString i}@" d;
    }
    // d.extraConfig
  ) cfg.daemons;

  settings = lib.recursiveUpdate (
    {
      refresh_interval_secs = cfg.refreshIntervalSecs;
      stale_after_secs = cfg.staleAfterSecs;
    }
    // lib.optionalAttrs (cfg.daemons != [ ]) {
      daemons = daemonSettings;
    }
    // lib.optionalAttrs (isGateway && cfg.serve != null) {
      serve = {
        listen = cfg.serve.listen;
        auth_token = tokenValue "@DUMBARP_SERVE_TOKEN@" cfg.serve;
      };
    }
    // lib.optionalAttrs (isRouterd && cfg.gateway != null) {
      gateway = {
        endpoint = cfg.gateway.endpoint;
        auth_token = tokenValue "@DUMBARP_GATEWAY_TOKEN@" cfg.gateway;
        device_overrides = cfg.gateway.deviceOverrides;
      };
    }
    // lib.optionalAttrs isRouterd {
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
    ${lib.concatMapStrings (s: ''
      token=$(cat "$CREDENTIALS_DIRECTORY/${s.id}")
      # Escape backslashes then double quotes for safe TOML string embedding.
      escaped=$(printf '%s' "$token" \
        | ${pkgs.gnused}/bin/sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
      ${pkgs.gnused}/bin/sed -i "s|${s.placeholder}|$escaped|g" ${runtimeConfigPath}
    '') secrets}
  '';

  loadCredentials = map (s: "${s.id}:${s.file}") secrets;

  tokenOptions = subject: {
    authToken = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        ${subject} Written into the config file in the Nix store — readable by
        any local user. Prefer the matching `authTokenFile` for production; if
        both are set, the file wins.
      '';
    };

    authTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        ${subject} Loaded via systemd {option}`LoadCredential` and substituted
        into a runtime config under {file}`/run/${serviceName}/`, keeping the
        token out of the Nix store.
      '';
    };
  };

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
    }
    // tokenOptions "Bearer token for this daemon's API.";
  };

  serveType = lib.types.submodule {
    options = {
      listen = lib.mkOption {
        type = lib.types.str;
        default = "0.0.0.0:1029";
        description = "Address:port to serve the daemon list on.";
      };
    }
    // tokenOptions "Bearer token clients must present to read `/daemons`.";
  };

  upstreamType = lib.types.submodule {
    options = {
      endpoint = lib.mkOption {
        type = lib.types.str;
        example = "http://10.0.0.1:1029";
        description = "Base URL of the dumbarp-gateway serving the daemon list.";
      };

      deviceOverrides = lib.mkOption {
        type = lib.types.attrsOf lib.types.str;
        default = { };
        example = {
          homelab = "eno1";
        };
        description = ''
          Per-daemon egress interface overrides, keyed by daemon name. Only
          needed where this router's interface naming differs from what the
          gateway advertises.
        '';
      };
    }
    // tokenOptions "Bearer token presented to the gateway.";
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
      description = "How often to poll upstream and reconcile routes.";
    };

    staleAfterSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = ''
        Keep serving the last-known result for this long when a fetch fails, so
        transient outages don't flap routes. Must be at least
        {option}`refreshIntervalSecs`.
      '';
    };

    daemons = lib.mkOption {
      type = lib.types.listOf daemonType;
      default = [ ];
      description =
        "The dumbarpd instances to poll directly."
        + lib.optionalString isRouterd " Mutually exclusive with {option}`gateway`.";
    };

    extraConfig = lib.mkOption {
      type = tomlFormat.type;
      default = { };
      description = "Extra keys merged into the rendered TOML config.";
    };
  }
  // lib.optionalAttrs isGateway {
    serve = lib.mkOption {
      type = lib.types.nullOr serveType;
      default = null;
      description = ''
        Expose the resolved daemon list over HTTP so {command}`dumbarp-routerd`
        instances can learn it from here instead of repeating it on every
        router. Leave null to keep the gateway poll-only with no listener.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the TCP port from {option}`serve.listen` in the firewall.";
    };
  }
  // lib.optionalAttrs isRouterd {
    gateway = lib.mkOption {
      type = lib.types.nullOr upstreamType;
      default = null;
      description = ''
        Learn the daemon list from a {command}`dumbarp-gateway` that has
        {option}`serve` enabled, so this router needs no per-daemon config.
        Mutually exclusive with {option}`daemons`.
      '';
    };

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
    ++ lib.optionals isGateway [
      {
        assertion = cfg.daemons != [ ];
        message = "services.${serviceName}.daemons must list at least one entry.";
      }
      {
        assertion = cfg.serve == null || (cfg.serve.authToken != null) || (cfg.serve.authTokenFile != null);
        message = "services.${serviceName}.serve: set either `authToken` or `authTokenFile`.";
      }
    ]
    ++ lib.optionals isRouterd [
      {
        assertion = (cfg.gateway != null) != (cfg.daemons != [ ]);
        message = "services.${serviceName}: set exactly one of `gateway` or `daemons`.";
      }
      {
        assertion =
          cfg.gateway == null || (cfg.gateway.authToken != null) || (cfg.gateway.authTokenFile != null);
        message = "services.${serviceName}.gateway: set either `authToken` or `authTokenFile`.";
      }
      {
        assertion = cfg.dscp.ifaces != [ ];
        message = "services.${serviceName}.dscp.ifaces must list at least one interface.";
      }
    ];

    environment.etc = lib.mkIf (!useFileSecret) {
      "${configFileName}".source = baseConfigFile;
    };

    networking.firewall = lib.mkIf (isGateway && cfg.openFirewall && cfg.serve != null) {
      allowedTCPPorts = [ (lib.toInt (lib.last (lib.splitString ":" cfg.serve.listen))) ];
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
      // lib.optionalAttrs isRouterd {
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
      // lib.optionalAttrs isGateway {
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
