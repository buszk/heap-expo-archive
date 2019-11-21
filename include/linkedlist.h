/*
 *  linkedlist.h
 *  template class for the list
 * 
 *  Originally implementd by gavra0 at https://github.com/gavra0/ConcLinkedList
 *  Modified to fit specific need of mine. 
 * 
 *  Description:
 *   Lock-free linkedlist implementation of Harris' algorithm
 *   "A Pragmatic Implementation of Non-Blocking Linked Lists" 
 *   T. Harris, p. 300-314, DISC 2001.
 * 
 *  Modification:
 *   Remove search and contains operations
 *   Assume the remove caller has the iterator
 */

#ifndef LLIST_H_
#define LLIST_H_


#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <memory>

#include "atomic_ops_if.h"

#ifdef DEBUG
#define IO_FLUSH                        fflush(NULL)
#endif


template <typename T>
struct node 
{
	struct node<T> *next;
	T data;
  uintptr_t padding;

  node(T, struct node<T>*);
};

template <typename T>
struct fl_node {
  uintptr_t padding_1;
  T padding_2;
  struct fl_node<T> *next;

};

template <typename T, class Alloc = std::allocator<node<T>>>
class llist 
{
private:
	node<T> *head;
	uint32_t list_size;
  uint64_t fl_aba_head;
  Alloc _alloc;
  /*
  * The five following functions handle the low-order mark bit that indicates
  * whether a node is logically deleted (1) or not (0).
  *  - is_marked_ref returns whether it is marked, 
  *  - (un)set_marked changes the mark,
  *  - get_(un)marked_ref sets the mark before returning the node.
  */
  inline int
  is_marked_ref(node<T> * i) 
  {
    return (int) (((uintptr_t)i) & 0x1L);
  }

  inline node<T> *
  unset_mark(node<T> * i)
  {
    uintptr_t p = (uintptr_t) i;
    p &= ~0x1L;
    return (node<T> *) p;
  }

  inline node<T> *
  set_mark(node<T> * i) 
  {
    uintptr_t p = (uintptr_t) i;
    p |= 0x1L;
    return (node<T> *) p;
  }

  inline node<T> *
  get_unmarked_ref(node<T> * w) 
  {
    return (node<T> *) (((uintptr_t)w) & ~0x1L);
  }

  inline node<T> *
  get_marked_ref(node<T> * w) 
  {
    return (node<T> *) (((uintptr_t)w) | 0x1L);
  }
  /*
  * The three following functions handle the 64-bit number 
  *  that is consisted of aba number (high 16 bits) and
  *  head to free list node (low 48 bits)
  * 
  * This works because current 48-bit addressing ensures 
  *  that the top 16 bits of pointers are not used. 
  */
  inline fl_node<T>* 
  get_fl_head(uint64_t n) {
    return (fl_node<T>*)(n & 0xffffffffffff);
  }

  inline uint16_t 
  get_fl_aba(uint64_t n) {
    return (uint16_t) ((n & 0xffff000000000000) >> (48));
  }

  inline uint64_t 
  get_fl(uint16_t aba, fl_node<T>* ptr) {
    return ((uint64_t)aba << 48) | (uintptr_t)ptr;
  }

public:
  llist();
  ~llist();

  node<T>* add(T);
  void remove(node<T>*);
  int size();
  int check();
  int check_flist();
  void print();
  void clear();

  /* Some code that helps iterating */
  node<T>* begin() {
    if (head == NULL)
      return NULL;
    if (!is_marked_ref(head->next))
      return head;
    return iter_next(head);
  }
  node<T>* iter_next(node<T>* cur) {
    node<T>* res;
    if (cur == NULL || get_unmarked_ref(cur->next) == NULL)
      return NULL;
    res = get_unmarked_ref(cur->next);
    while (res) {
      if (!is_marked_ref(res->next))
        return res;
      res = get_unmarked_ref(res->next);
    }
    return NULL;
  }
};

template <typename T>
node<T>::node(T val, node<T>* _next) {
  data = val;
  next = _next;
  padding = 0;
}

template <typename T, class Alloc>
llist<T, Alloc>::llist()
{
  //printf("Create list method\n");
  head = NULL;
  list_size = 0;
  fl_aba_head = 0;
}

template <typename T, class Alloc>
llist<T, Alloc>::~llist()
{
  //printf("Delete list method\n");
  node<T> *n = head;
  while (head) {
    head = get_unmarked_ref(head->next);
    _alloc.deallocate(n, 1);
    n = head;
  }
}

template <typename T, class Alloc>
void llist<T, Alloc>::clear()
{
  //printf("Delete list method\n");
  node<T> *n = head;
  while (head) {
    head = get_unmarked_ref(head->next);
    _alloc.deallocate(n, 1);
    n = head;
  }
}

template <typename T, class Alloc>
int llist<T, Alloc>::size() 
{ 
  return list_size; 
} 

/*
 * add inserts a new node with the given value val in the list
 * 
 * If there is a position in free list, it tries to use the node
 *  from free list. Otherwise, it allocates a new node as the new head.
 */
template <typename T, class Alloc>
node<T>* llist<T, Alloc>::add(T val)
{
  
  fl_node<T> *fl_head, *fl_next;
  node<T> *left, *unmarked;
  uint16_t fl_aba;
  uint64_t fl_aba_head_last, fl_aba_head_new;
  fl_head = fl_next = NULL;
  left = unmarked = NULL;

  do {
    fl_aba_head_last = fl_aba_head;
    fl_head = get_fl_head(fl_aba_head_last);
    fl_aba = get_fl_aba(fl_aba_head_last);
    fl_next = fl_head ? fl_head->next : NULL;
    fl_aba_head_new = get_fl(fl_aba+1, fl_next);
  } while(fl_head && CAS_PTR(&fl_aba_head, fl_aba_head_last, fl_aba_head_new) != fl_aba_head_last);

  if (fl_head) {
    left = (node<T>*) fl_head;
    if (is_marked_ref(left->next)) {
      left->next = get_unmarked_ref(left->next);
      left->data = val;
      FAI_U32(&(list_size));
      return left;
    }
  }
  node<T> *new_elem = _alloc.allocate(1);
  new_elem->data = val;
  new_elem->next = NULL;
  new_elem->padding = 0;

  do {
    left = head;
    new_elem->next = left;
  } while(CAS_PTR(&head, left, new_elem) != left);
  FAI_U32(&(list_size));
  return new_elem;
}

/*
 * remove deletes a node with givien iterator 
 * It adds the node to free list, so the node can be later reused.
 */
template <typename T, class Alloc>
void llist<T, Alloc>::remove(node<T>* node)
{
  fl_node<T> *fl_new_node, *fl_head;
  uint64_t fl_aba_head_last, fl_aba_head_new;
  uint16_t fl_aba;
  
  if (node->next == get_marked_ref(node->next)) 
    return;
  
  node->next = get_marked_ref(node->next);
  fl_new_node = (fl_node<T>*) node;

  while (1) {
    fl_aba_head_last = fl_aba_head;
    fl_head = get_fl_head(fl_aba_head_last);
    fl_aba = get_fl_aba(fl_aba_head_last);
    fl_new_node->next = fl_head;
    fl_aba_head_new = get_fl(fl_aba+1, fl_new_node);
    if (CAS_PTR(&(fl_aba_head), fl_aba_head_last, fl_aba_head_new) == fl_aba_head_last){
      FAD_U32(&(list_size));
      return;
    }
  }
}

/*
 * check returns the size of the list by iterating through all nodes.
 * 
 * This function may ends in infinite loop if some terrible bug is present.
 */
template <typename T, class Alloc>
int llist<T, Alloc>::check() {
  node<T> *n, *unmarked;
  size_t size;
  n = head;
  size = 0;
  while (n)
  {
    unmarked = get_unmarked_ref(n->next);
    if (n->next == unmarked) size ++;
    n = unmarked;
  }
  return size;
}

/*
 * print output current list into stdout
 * 
 *  This function may ends in infinite loop if some terrible bug is present.
 */
template <typename T, class Alloc>
void llist<T, Alloc>::print() {
  printf("free list head: [%016lx] \n", (uintptr_t)get_fl_head(fl_aba_head));
  node<T> *n, *unmarked;
  n = head;
  while (n)
  {
    unmarked = get_unmarked_ref(n->next);
    printf("[%016lx] next: %016lx data: %08lx pad: %015lx\n", (uintptr_t)n, (uintptr_t)n->next, (uintptr_t)n->data, (uintptr_t)n->padding);
    n = unmarked;
  }
}

/*
 * check_flist returns the number of nodes in free list.
 * 
 *  This function may ends in infinite loop if some terrible bug is present.
 */
template <typename T, class Alloc>
int llist<T, Alloc>::check_flist() {
  node<T> *n, *unmarked;
  size_t size;
  n = head;
  size = 0;
  while (n)
  {
    unmarked = get_unmarked_ref(n->next);
    if (n->next != unmarked) size ++;
    n = unmarked;
  }
  return size;
}

#endif
