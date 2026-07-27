import ./reconciler-module.nix {
  serviceName = "dumbarp-routerd";
  description = "dumbarp router-node reconciler and DSCP datapath";
  dscp = true;
}
