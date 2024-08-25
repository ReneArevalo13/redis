#include <assert.h>
#include <stdlib.h>
#include "hashtable.h"



// n must be a power of 2
static void h_init(HTab *htab, size_t n) {
    assert(n > 0 && ((n - 1) & n) == 0);
    htab->tab = (HNode **)calloc(sizeof(HNode *), n);
    htab->mask = n - 1;
    htab->size = 0;
}

// hashtable insertion
// list insertion
static void h_insert(HTab *htab, HNode *node) {
    size_t pos = node->hcode & htab->mask;  // slot index
    HNode *next = htab->tab[pos];           // prepend the list
    node->next = next;
    htab->tab[pos] = node;
    htab->size++;
}

// hashtable lookup subroutine
// Pay attention to the return value. It returns the address of
// the parent pointer that owns the target node,
// which can be used to delete the target node.
static HNode **h_lookup(HTab *htab, HNode *key, bool (*eq)(HNode *, HNode *))
{
    if (!htab->tab) {
        return NULL;
    }

    size_t pos = key->hcode & htab->mask;
    HNode **from = &htab->tab[pos];       // incoming pointer to the result
    for(HNode *cur; (cur = *from) != NULL; from = &cur->next) {
        if (cur->hcode == key->hcode && eq(cur,key)) {
            return from;
        }
    }
    return NULL;
}

// remove a node from the chain and return the pointer to that deleted node
static HNode *h_detach(HTab *htab, HNode **from) {
    HNode *node = *from;   // pointer node is pointing to the dereferenced ** from (single *)
    *from = node->next;
    htab->size--;
    return node;
}

const size_t k_resizing_work = 128;    // constant work

// moves some keys to the new table, it's triggered from both hashmap lookup and updates.
static void hm_help_resizing(HMap *hmap) {
    size_t nwork = 0;
    while (nwork < k_resizing_work && hmap->ht2.size > 0) {
        // scan for nodes from ht2 and move them to ht1
        HNode **from = &hmap->ht2.tab[hmap->resizing_pos];
        if(!*from) {
            hmap->resizing_pos++;
            continue;
        }
        h_insert(&hmap->ht1, h_detach(&hmap->ht2, from));
        nwork++;
    }
    if (hmap->ht2.size == 0 && hmap->ht2.tab) {
        // done
        free(hmap->ht2.tab);
        hmap->ht2 = HTab{};
    }
}

static void hm_start_resizing(HMap *hmap) {
    assert(hmap->ht2.tab == NULL);
    // create a bigger hashtable and swap them
    hmap->ht2 = hmap->ht1;
    h_init(&hmap->ht1, (hmap->ht1.mask + 1) * 2);
    hmap->resizing_pos = 0;
}
// Lookup checks both tables (ht1, ht2)
HNode *hm_lookup(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
    hm_help_resizing(hmap);
    HNode **from = h_lookup(&hmap->ht1, key, eq);
    from = from ? from : h_lookup(&hmap->ht2, key, eq);
    return from ? *from : NULL;
}

const size_t k_max_load_factor = 8;

void hm_insert(HMap *hmap, HNode *node) {
    if (!hmap->ht1.tab) {
        h_init(&hmap->ht1, 4);        // 1. Initialize the table if it's empty
    }
    h_insert(&hmap->ht1, node);       // 2. Insert the key into the table.

    if (!hmap->ht2.tab) {             // 3. Check the load factor
        size_t load_factor = hmap->ht1.size / (hmap->ht1.mask + 1);
        if (load_factor >= k_max_load_factor) {
            hm_start_resizing(hmap);  // create a larger table   
        }
    }
    hm_help_resizing(hmap);           // 4. Move some keys into the newer table
}

HNode *hm_pop(HMap *hmap, HNode *key, bool (*eq)(HNode *, HNode *)) {
    hm_help_resizing(hmap);
    if (HNode **from = h_lookup(&hmap->ht1, key, eq)) {
        return h_detach(&hmap->ht1, from);
    }
    if (HNode **from = h_lookup(&hmap->ht2, key, eq)) {
        return h_detach(&hmap->ht2, from);
    }
    return NULL;
}

size_t hm_size(HMap *hmap) {
    return hmap->ht1.size + hmap->ht2.size;
}

void hm_destroy(HMap *hmap) {
    free(hmap->ht1.tab);
    free(hmap->ht2.tab);
    *hmap = HMap{};
}