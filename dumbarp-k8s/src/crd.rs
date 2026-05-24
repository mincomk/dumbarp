use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "cilium.io",
    version = "v2",
    kind = "CiliumLoadBalancerIPPool",
    plural = "ciliumloadbalancerippools",
    shortname = "ippool"
)]
pub struct CiliumLoadBalancerIPPoolSpec {
    pub blocks: Vec<CiliumLoadBalancerIPPoolIPBlock>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct CiliumLoadBalancerIPPoolIPBlock {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
}
