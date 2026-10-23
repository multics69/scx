#pragma once

#ifdef __BPF__
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <bpf_arena_spin_lock.h>
#endif /* __BPF__ */

#include <scx/const-defs.h>
#include <lib/sdt_task.h>

#define RB_MAXLVL_PRINT (16)

struct rbnode;

typedef struct rbnode __arena rbnode_t;

struct rbnode {
	rbnode_t *parent;
	union {
		struct {
			rbnode_t *left;
			rbnode_t *right;
		};

		rbnode_t *child[2];
	};
	uint64_t key;
	/* Used as a linked list or to store KV pairs. */
	union {
		rbnode_t *next;
		uint64_t value;
	};
	bool is_red;
};

/* 
 * Does the rbtree allocate is own nodes, or do they get
 * allocated by the caller?
 */
enum rbtree_alloc {
	RB_ALLOC,
	RB_NOALLOC,
};

/*
 * Specify the behavior of rbtree insertions when the key is
 * already present in the tree.
 *
 * RB_DEFAULT: Default behavior, reject the new insert.
 *
 * RB_UPDATE: Update the existing value in the rbtree.
 * This updates the node itself, not just the value in
 * the existing node.
 *
 * RB_DUPLICATE: Allow nodes with identical keys in the rbtree.
 * Nodes with identical keys are kept in insertion order, so
 * rb_least() and rb_pop() return the oldest of them. Finding
 * or removing by key acts on any of them.
 */
enum rbtree_insert_mode {
	RB_DEFAULT,
	RB_UPDATE,
	RB_DUPLICATE,
};

struct rbtree {
	/*
	 * Writer fields. They are not aligned, so a struct that embeds the tree
	 * can keep its own writer fields on the same cache line.
	 */
	rbnode_t *root;
	rbnode_t *freelist;
	enum rbtree_alloc alloc;
	enum rbtree_insert_mode insert;

	/*
	 * The leftmost node and the node count. The writer keeps them current,
	 * and readers may read them without the writer's lock (see rb_first()
	 * and friends). They change with the head and are read by every peek,
	 * so they sit on their own cache line, apart from root.
	 */
	struct {
		rbnode_t *first;
		uint64_t nr;
	} __attribute__((aligned(SCX_CACHELINE_SIZE)));
};

typedef struct rbtree __arena rbtree_t;

int scx_rb_init(void);

#ifdef __BPF__
u64 rb_create_internal(enum rbtree_alloc alloc, enum rbtree_insert_mode insert);
#define rb_create(alloc, insert) ((rbtree_t *)rb_create_internal((alloc), (insert)))

/*
 * Initialize a tree embedded in another arena object. The object must be
 * allocated with SCX_CACHELINE_SIZE alignment for the lockless fields to sit
 * on their own cache line. rb_destroy() is only for trees from rb_create().
 */
int rb_init(rbtree_t __arg_arena *rbtree, enum rbtree_alloc alloc,
	    enum rbtree_insert_mode insert);

int rb_destroy(rbtree_t __arg_arena *rbtree);
int rb_insert(rbtree_t *rbtree, u64 key, u64 value);
int rb_remove(rbtree_t *rbtree, u64 key);
int rb_find(rbtree_t *rbtree, u64 key, u64 *value);
int rb_print(rbtree_t *rbtree);
int rb_least(rbtree_t *rbtree, u64 *key, u64 *value);
int rb_pop(rbtree_t *rbtree, u64 *key, u64 *value);

int rb_insert_node(rbtree_t *rbtree, rbnode_t *node);
int rb_remove_node(rbtree_t *rbtree, rbnode_t *node);
u64 rb_node_alloc_internal(rbtree_t *rbtree, u64 key, u64 value);
#define rb_node_alloc(rbtree, key, value) ((rbnode_t *)rb_node_alloc_internal((rbtree), (key), (value)))
int rb_node_free(rbtree_t *rbtree, rbnode_t *rbnode);

int rb_integrity_check(rbtree_t *rbtree);

/*
 * Lockless reads of the head and the node count, like scx_bpf_dsq_peek() and
 * scx_bpf_dsq_nr_queued() for kernel DSQs. They need not be called under the
 * writer's lock, so they are advisory: the tree may change before the caller
 * acts on the result.
 *
 * The head pointer alone tells whether the tree is empty and which node leads
 * it. The writer releases it after the node is linked, so the node's fields,
 * key included, are read through the pointer in dependency order. The node
 * may have left the tree by then. The count is a separate read and need not
 * agree with the head.
 */
static __always_inline rbnode_t *rb_first(rbtree_t *rbtree)
{
	return READ_ONCE(rbtree->first);
}

/* -ENOENT if the tree is empty, 0 with the leftmost key in @key otherwise. */
static __always_inline int rb_first_key(rbtree_t *rbtree, u64 *key)
{
	rbnode_t *first = READ_ONCE(rbtree->first);

	if (!first)
		return -ENOENT;

	*key = READ_ONCE(first->key);
	return 0;
}

static __always_inline u64 rb_nr_nodes(rbtree_t *rbtree)
{
	return READ_ONCE(rbtree->nr);
}

#endif /* __BPF__ */
