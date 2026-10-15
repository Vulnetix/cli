use alloy_primitives::B256;
use std::str::FromStr;

pub fn genesis() -> B256 {
    B256::from_str("@@sample:0[x]d4[e]56[7]40[f]87[6]ae[f]8c[0]10[b]86[a]40[d]5f[5]67[4]5a[1]18[d]09[0]6a[3]4e[6]9a[e]c8[c]0d[b]1c[b]8f[a]3@@").unwrap()
}

pub fn root() -> B256 {
    "@@sample:0[x]56[e]81[f]17[1]bc[c]55[a]6f[f]83[4]5e[6]92[c]0f[8]6e[5]b4[8]e0[1]b9[9]6c[a]dc[0]01[6]22[f]b5[e]36[3]b4[2]1@@".parse().unwrap()
}
