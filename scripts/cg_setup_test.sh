#!/usr/bin/bash

echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control

# ==========================================================
# Config 01: a single level, half CPU
mkdir -p /sys/fs/cgroup/test01_l1

echo "+cpu" > /sys/fs/cgroup/test01_l1/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test01_l1/cpu.max

# -------------
# Test 01-01 (l1 ,l2)
# echo $$ > /sys/fs/cgroup/test01_l1/cgroup.procs
#
# TODO (l1, l2): rbtree-ATQ
# - stress-ng -c 64: task stall, "Only child is black", "scx_atq_pop: error -22"
#
# GOOD (l1): minheap-ATQ

# ==========================================================
# Config 02: a single level, two CPUs
mkdir -p /sys/fs/cgroup/test02_l1

echo "+cpu" > /sys/fs/cgroup/test02_l1/cgroup.subtree_control

echo "200000 100000 " > /sys/fs/cgroup/test02_l1/cpu.max

# -------------
# Test 02-01 (l1, l2)
# echo $$ > /sys/fs/cgroup/test02_l1/cgroup.procs
#
# GOOD
#
# GOOD (l1): minheap-ATQ

# ==========================================================
# Config 03: two-level, half CPU
mkdir -p /sys/fs/cgroup/test03_l1
mkdir -p /sys/fs/cgroup/test03_l1/l2-a
mkdir -p /sys/fs/cgroup/test03_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test03_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test03_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test03_l1/l2-b/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test03_l1/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test03_l1/l2-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test03_l1/l2-b/cpu.max

# -------------
# Test 03-01 (l1, l2): running on a single cgroup
# echo $$ > /sys/fs/cgroup/test03_l1/l2-a/cgroup.procs
#
# TODO (l1, l2)
# - stress-ng -c 128: task stall at terminating the stress-ng?
#   - When terminating,
#     - [scx_cgroup_bw_put_aside:1343] ERROR:Failed to insert a task to BTQ: -110
#
#   - rbtree: removed black node has no sibling
#   - scx_atq_pop: error -22
#
#   - Only child is black
#   - scx_atq_pop: error -22
#
#   - Node unexpectedly red
#   - scx_atq_pop: error -22
#
# TODO (l2)
# - stress-ng -c 128: 100% cpu util
#
# GOOD (l1, l2): minheap-ATQ

# -------------
# Test 03-02 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test03_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test03_l1/l2-b/cgroup.procs
#
# TODO (l1)
# - stress-ng -c 8 and stress-ng -c 8 
# - stress-ng -c 16 and stress-ng -c 16
#   - task stall
#   - [scx_cgroup_bw_put_aside:1343] ERROR:Failed to insert a task to BTQ: -110
#
# GOOD (l2)
#
# GOOD (l1): minheap-ATQ
# XXX TODO (l1, l2): minheap-ATQ
#   - stress-ng -c 32 vs. 32: 35% vs. 15% (not 25% vs. 25%)
#   - stress-ng -c 64 vs. 64: 70% (not 50%)
#   - stress-ng -c 128 vs. 128: 120%?

# ==========================================================
# Config 04: two-level, two CPUs
mkdir -p /sys/fs/cgroup/test04_l1
mkdir -p /sys/fs/cgroup/test04_l1/l2-a
mkdir -p /sys/fs/cgroup/test04_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test04_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test04_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test04_l1/l2-b/cgroup.subtree_control

echo "200000 100000" > /sys/fs/cgroup/test04_l1/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test04_l1/l2-a/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test04_l1/l2-b/cpu.max

# -------------
# Test 04-01 (l1, l2): running on a single cgroup
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs
#
# GOOD
#
# TODO (l2)
#  - bpf_trace_printk: rbtree: removed black node has no sibling
#  - scx_atq_pop: error -22
#  - scx_atq_pop: error -2
#
# GOOD (l1, l2): minheap-ATQ

# -------------
# Test 04-02: running on two cgroups
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test04_l1/l2-b/cgroup.procs
#
# GOOD
#
# GOOD (l1): minheap-ATQ
# XXX TODO (l2): minheap-ATQ: 128 vs. 128 => 150% : 50% (not 100% : 100%)


# ==========================================================
# Config 05: three-level, half CPU
mkdir -p /sys/fs/cgroup/test05_l1
mkdir -p /sys/fs/cgroup/test05_l1/l2-a
mkdir -p /sys/fs/cgroup/test05_l1/l2-a/l3-x
mkdir -p /sys/fs/cgroup/test05_l1/l2-a/l3-y
mkdir -p /sys/fs/cgroup/test05_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test05_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-a/l3-y/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test05_l1/l2-b/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test05_l1/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-a/l3-y/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test05_l1/l2-b/cpu.max

# -------------
# Test 05-01 (l1, l2): running on a single cgroup at level three
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs
#
# GOOD
#
# TODO (l2)
# - Only child is black
# - scx_atq_pop: error -22
#
# GOOD (l1, l2): minheap-ATQ

# -------------
# Test 05-02 (l1, l2): running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs
#
# GOOD
#
# TODO (l2)
# - stress-ng -c 128: 100%?
#
# GOOD (l1, l2): minheap-ATQ

# -------------
# Test 05-03 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs
#
# GOOD
#
# TODO (l2)
# - stress-ng -c 16 and stress-ng -c 16
#   - ERROR:Failed to insert a task to BTQ: -110
#
# GOOD (l1, l2): minheap-ATQ
# XXX TODO (l2): minheap-ATQ: 128 vs. 128 => 150% not 50%

# ==========================================================
# Config 06: three-level, two CPUs
mkdir -p /sys/fs/cgroup/test06_l1
mkdir -p /sys/fs/cgroup/test06_l1/l2-a
mkdir -p /sys/fs/cgroup/test06_l1/l2-a/l3-x
mkdir -p /sys/fs/cgroup/test06_l1/l2-a/l3-y
mkdir -p /sys/fs/cgroup/test06_l1/l2-b

echo "+cpu" > /sys/fs/cgroup/test06_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-a/l3-y/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test06_l1/l2-b/cgroup.subtree_control

echo "200000 100000" > /sys/fs/cgroup/test06_l1/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-a/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-a/l3-y/cpu.max
echo "200000 100000" > /sys/fs/cgroup/test06_l1/l2-b/cpu.max

# -------------
# Test 06-01 (l1, l2): running on a single cgroup at level three
# echo $$ > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.procs
#
# TODO (l1, l2)
# - stress-ng -c 256
#   - rbtree: removed black node has no sibling
#   - scx_atq_pop: error -22
#
# GOOD (l1, l2): minheap-ATQ

# -------------
# Test 06-02 (l1, l2): running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test06_l1/l2-b/cgroup.procs
#
# TODO (l1)
# - stress-ng -c 512
#   - Only child is black
#   - scx_atq_pop: error -22
#
# GOOD (l2)
#
# GOOD (l1, l2): minheap-ATQ

# -------------
# Test 06-03 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test06_l1/l2-b/cgroup.procs
#
# GOOD
#
# GOOD (l1, l2): minheap-ATQ


# ==========================================================
# Config 07: deep hierarchy (level 8), half CPU
mkdir -p /sys/fs/cgroup/test07_l1
mkdir -p /sys/fs/cgroup/test07_l1/l2-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a
mkdir -p /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a

echo "+cpu" > /sys/fs/cgroup/test07_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test07_l1/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cpu.max
echo "50000 100000" > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cpu.max

# -------------
# Test 07-01 (l1, l2): running on a single cgroup at the leaf level
# echo $$ > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.procs
#
# GOOD
#
# TODO (l2)
# - stress-ng -c 256: "Only child is black" "scx_atq_pop: error -22"
#
# GOOD (l1, l2): minheap-ATQ


# ==========================================================
# Config 08: deep hierarchy (level 8), 128 CPUs
mkdir -p /sys/fs/cgroup/test08_l1
mkdir -p /sys/fs/cgroup/test08_l1/l2-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a
mkdir -p /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a

echo "+cpu" > /sys/fs/cgroup/test08_l1/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cgroup.subtree_control
echo "+cpu" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.subtree_control

echo "12800000 100000" > /sys/fs/cgroup/test08_l1/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/cpu.max
echo "12800000 100000" > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cpu.max

# -------------
# Test 08-01: running on a single cgroup at the leaf level
# echo $$ > /sys/fs/cgroup/test08_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.procs
#
# GOOD
#
# TODO (l2)
#   - stress-ng -c 64 => 3000% often?
#
# GOOD (l1, l2): minheap-ATQ
# XXX TODO (l2): 64 => 30000% not 4000%?

# ==========================================================
# Config 09: a single level, half CPU, long period
mkdir -p /sys/fs/cgroup/test09_l1

echo "+cpu" > /sys/fs/cgroup/test09_l1/cgroup.subtree_control

echo "500000 1000000" > /sys/fs/cgroup/test09_l1/cpu.max

# -------------
# Test 09-01
# echo $$ > /sys/fs/cgroup/test09_l1/cgroup.procs
#
# GOOD
#
# GOOD (l1, l2): minheap-ATQ

# ==========================================================
# Config 10: a single level, two CPUs, long period
mkdir -p /sys/fs/cgroup/test10_l1

echo "+cpu" > /sys/fs/cgroup/test10_l1/cgroup.subtree_control

echo "2000000 1000000 " > /sys/fs/cgroup/test10_l1/cpu.max

# -------------
# Test 10-01
# echo $$ > /sys/fs/cgroup/test10_l1/cgroup.procs
#
# GOOD
#
# GOOD (l1, l2): minheap-ATQ

# ==========================================================
# Config 11: a single level, half CPU, short period
mkdir -p /sys/fs/cgroup/test11_l1

echo "+cpu" > /sys/fs/cgroup/test11_l1/cgroup.subtree_control

echo "5000 10000" > /sys/fs/cgroup/test11_l1/cpu.max

# -------------
# Test 11-01
# echo $$ > /sys/fs/cgroup/test11_l1/cgroup.procs
#
# GOOD
#
# GOOD (l1, l2): minheap-ATQ

# ==========================================================
# Config 12: a single level, two CPUs, short period
mkdir -p /sys/fs/cgroup/test12_l1

echo "+cpu" > /sys/fs/cgroup/test12_l1/cgroup.subtree_control

echo "20000 10000 " > /sys/fs/cgroup/test12_l1/cpu.max

# -------------
# Test 12-01
# echo $$ > /sys/fs/cgroup/test12_l1/cgroup.procs
#
# GOOD
#
# GOOD (l1, l2): minheap-ATQ
