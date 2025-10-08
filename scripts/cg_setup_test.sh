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
# TODO
# - stress-ng -c 64: 101% (50% more)
# - stress-ng -c 32: 15% more CPU bw was used.

# ==========================================================
# Config 02: a single level, two CPUs
mkdir -p /sys/fs/cgroup/test02_l1

echo "+cpu" > /sys/fs/cgroup/test02_l1/cgroup.subtree_control

echo "200000 100000 " > /sys/fs/cgroup/test02_l1/cpu.max

# -------------
# Test 02-01 (l1, l2)
# echo $$ > /sys/fs/cgroup/test02_l1/cgroup.procs
#
# TODO
# - stress-ng -c 64: 5% more CPU bw was used.

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
# TODO
# - stress-ng -c 128: task stall at terminating the stress-ng?
#   - [scx_cgroup_bw_put_aside:1343] ERROR:Failed to insert a task to BTQ: -110
#
#   - rbtree: removed black node has no sibling
#   - scx_atq_pop: error -22
#
#   - Only child is black
#   - scx_atq_pop: error -22
#
#   - [replenish_timerfn:1447] ERROR:Incorrect replenish state: 2 -- 0 => 1
#   - Node unexpectedly red
#   - scx_atq_pop: error -22

# -------------
# Test 03-02 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test03_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test03_l1/l2-b/cgroup.procs
#
# TODO
# - stress-ng -c 32 and stress-ng -c 32 
#   - "dispatch buffer overflow" error (l1)
#   - "task stall" (l2)
#     - [scx_cgroup_bw_put_aside:1341] ERROR:Failed to insert a task to BTQ: -110
#     - Node unexpectedly red
#     - scx_atq_pop: error -22

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
# TODO
# - stress-ng -c 4: 25% more CPU bw

# -------------
# Test 04-02: running on two cgroups
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test04_l1/l2-b/cgroup.procs
#
# GOOD


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

# -------------
# Test 05-02 (l1, l2): running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs
#
# GOOD

# -------------
# Test 05-03 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs
#
# TODO (l2)
# - task stall (when terminating/forking tasks)
#   - Node unexpectedly red or Only child is black
#   - scx_atq_pop: error -22

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
# TODO
# - stress-ng -c 256
#   - rbtree: removed black node has no sibling
#   - scx_atq_pop: error -22

# -------------
# Test 06-02 (l1, l2): running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test06_l1/l2-b/cgroup.procs
#
# TODO
# - stress-ng -c 512
#   - Only child is black
#   - scx_atq_pop: error -22

# -------------
# Test 06-03 (l1, l2): running on two cgroups
# echo $$ > /sys/fs/cgroup/test06_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test06_l1/l2-b/cgroup.procs
#
# GOOD


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
#   - stress-ng -c 32 => 3000% often?




