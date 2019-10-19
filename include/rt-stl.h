#ifndef RT_STL_H
#define RT_STL_H
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <list>
#include <unordered_map>

#include "rt-libc.h"

template <typename T>
class he_allocator {
public:
    he_allocator() = default;
    
    template <typename U> constexpr 
    he_allocator(const he_allocator<U>&) noexcept {}
    
    typedef T value_type;
    typedef T* pointer;
    typedef const T* const_pointer;
    typedef T& reference;
    typedef const T& const_reference;
    typedef std::size_t size_type ;
    typedef std::ptrdiff_t difference_type; 
    
    template <typename _Tp1>
    struct rebind {
        typedef he_allocator<_Tp1> other;
    };
    
    pointer allocate(size_t n) {
        if(n > size_t(-1) / sizeof(value_type)) throw std::bad_alloc();
        if(auto p = static_cast<pointer>(__malloc(n*sizeof(value_type)))) return p;
        throw std::bad_alloc();
    };

    void construct(pointer p, const_reference val) { new((void*)p) T(val); }

    void deallocate(pointer p, std::size_t) noexcept { __free(p); }

    void destroy(pointer p) noexcept { p->~T(); }

    template <typename U>
    bool operator==(const he_allocator<U>&) {return true;}
    
    template <typename U>
    bool operator!=(const he_allocator<U>&) {return false;}
};

template <typename T>
using he_vector = std::vector<T, he_allocator<T>>;

template <typename T>
using he_set = std::set<T, std::less<T>, he_allocator<T>>;

template <typename T>
using he_unordered_set = std::unordered_set<T, std::hash<T>, std::equal_to<T>, he_allocator<T>>;

template <typename Key, typename T>
using he_map = std::map<Key, T, std::less<Key>, he_allocator<std::pair<const Key, T>>>;

template <typename Key, typename T>
using he_unordered_map = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, he_allocator<std::pair<const Key, T>>>;

template <typename T>
using he_list = std::list<T, he_allocator<T>>;

template <typename T, typename Comp>
class he_sorted_list {
    private:
        Comp        cmp;

    public:
        size_t      max = 0;
        he_list<T>  list;

        bool check() {

            if (list.size() <= 1) return true;
            auto cur = list.begin();
            cur++;
            auto pre = list.begin();

            while (cur != list.end()) {
                assert(cmp.diff(*cur, *pre) > 0);
                cur++;
                pre++;
            }
            return true;
        }


        void insert(const T& val) {
            auto cur = list.begin();

            if ((int)cmp.diff(val, *cur) < 0) {
                //printf("beginning\n");
                list.insert(cur, val);
                return;
            }

            while (cur != list.end()) {
                //printf("diff: %d\n", cmp.diff(val, *cur));
                if ((int)cmp.diff(val, *cur) < 0) {
                    //printf("cur just below\n");
                    list.insert(cur, val);
                    return;
                } 
                else if (cmp.diff(val, *cur) == 0) {
                    //printf("cur equal\n");
                    *cur = val;
                    return;
                }
                //printf("cur inc\n");
                cur++;
            }

            if (cur == list.end()) {
                list.insert(list.end(), val);
            }
        }

        bool contains(const T& val) {
            auto cur = list.begin();

            while (cur != list.end()) {
                if ((int)cmp.diff(val, *cur) < 0) {
                    return false;
                }
                else if (cmp.diff(val, *cur) == 0) {
                    return true;
                }
                
                cur ++;
            }

            return false;

        }

        T*  find(const T& val) {
            auto cur = list.begin();

            while (cur != list.end()) {
                if ((int)cmp.diff(val, *cur) < 0) {
                    return nullptr;
                }
                else if (cmp.diff(val, *cur) == 0) {
                    return &*cur;
                }

                cur ++;
            }
            return nullptr;
        }

        void erase_lower(const T& val) {

            if (list.size() > max) {
                max = list.size();

            }
            auto cur = list.begin();

            while (cur != list.end()) {
                if ((int)cmp.diff(val, *cur) < 0) {
                    list.erase(list.begin(), cur);
                    break;
                }
                cur ++;
            }
            
        }
};
#endif
