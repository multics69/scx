#!/usr/bin/bash

echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control

# ==========================================================
# Config 01: a single level, half CPU
mkdir -p /sys/fs/cgroup/test01_l1

echo "+cpu" > /sys/fs/cgroup/test01_l1/cgroup.subtree_control

echo "50000 100000" > /sys/fs/cgroup/test01_l1/cpu.max

# -------------
# Test 01-01
# echo $$ > /sys/fs/cgroup/test01_l1/cgroup.procs

# ==========================================================
# Config 02: a single level, two CPUs
mkdir -p /sys/fs/cgroup/test02_l1

echo "+cpu" > /sys/fs/cgroup/test02_l1/cgroup.subtree_control

echo "200000 100000 " > /sys/fs/cgroup/test02_l1/cpu.max

# -------------
# Test 02-01
# echo $$ > /sys/fs/cgroup/test02_l1/cgroup.procs

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
# Test 03-01: running on a single cgroup
# echo $$ > /sys/fs/cgroup/test01_l1/l2-a/cgroup.procs

# -------------
# Test 03-02: running on two cgroups
# echo $$ > /sys/fs/cgroup/test01_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test01_l1/l2-b/cgroup.procs

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
# Test 04-01: running on a single cgroup
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs

# -------------
# Test 04-02: running on two cgroups
# echo $$ > /sys/fs/cgroup/test04_l1/l2-a/cgroup.procs
# echo $$ > /sys/fs/cgroup/test04_l1/l2-b/cgroup.procs


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
# Test 05-01: running on a single cgroup at level three
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs

# -------------
# Test 05-02: running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs
#
# -------------
# Test 05-03: running on two cgroups
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs


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
# Test 06-01: running on a single cgroup at level three
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs

# -------------
# Test 06-02: running on a single cgroup at level two
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs
#
# -------------
# Test 06-03: running on two cgroups
# echo $$ > /sys/fs/cgroup/test05_l1/l2-a/l3-x/cgroup.procs
# echo $$ > /sys/fs/cgroup/test05_l1/l2-b/cgroup.procs


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
# Test 07-01: running on a single cgroup at the leaf level
# echo $$ > /sys/fs/cgroup/test07_l1/l2-a/l3-a/l4-a/l5-a/l6-a/l7-a/l8-a/cgroup.procs


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




