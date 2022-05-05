# Copyright 2013-2022 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
#
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

"""
This module implements Version and version-ish objects.  These are:

Version
  A single version of a package.
VersionRange
  A range of versions of a package.
VersionList
  A list of Versions and VersionRanges.

All of these types support the following operations, which can
be called on any of the types::

  __eq__, __ne__, __lt__, __gt__, __ge__, __le__, __hash__
  __contains__
  satisfies
  overlaps
  union
  intersection
  concrete
"""
import numbers
import os
import re
import sys
from bisect import bisect_left
from functools import wraps
from typing import Sequence

if sys.version_info[0] >= 3:
    from functools import lru_cache
else:
    from functools32 import lru_cache

from six import string_types

import llnl.util.tty as tty
from llnl.util.filesystem import mkdirp, working_dir

import spack.error
import spack.paths
import spack.util.executable
import spack.util.spack_json as sjson
from spack.util.spack_yaml import syaml_dict


# break import cycle
def spack_caches():
    import spack.caches
    return spack.caches


__all__ = ['Version', 'VersionRange', 'VersionList', 'ver']

# Valid version characters
VALID_VERSION = re.compile(r'^[A-Za-z0-9_.-]+$')

# regex for a commit version
COMMIT_VERSION = re.compile(r'^[a-f0-9]{40}$')

# regex for version segments
SEGMENT_REGEX = re.compile(r'(?:(?P<num>[0-9]+)|(?P<str>[a-zA-Z]+))(?P<sep>[_.-]*)')

# regular expression for semantic versioning
SEMVER_REGEX = re.compile(".+(?P<semver>([0-9]+)[.]([0-9]+)[.]([0-9]+)"
                          "(?:-([0-9A-Za-z-]+(?:[.][0-9A-Za-z-]+)*))?"
                          "(?:[+][0-9A-Za-z-]+)?)")

# Infinity-like versions. The order in the list implies the comparison rules
infinity_versions = ['develop', 'main', 'master', 'head', 'trunk', 'stable']

iv_min_len = min(len(s) for s in infinity_versions)


def coerce_versions(a, b):
    """
    Convert both a and b to the 'greatest' type between them, in this order:
           Version < VersionRange < VersionList
    This is used to simplify comparison operations below so that we're always
    comparing things that are of the same type.
    """
    order = (CommitVersion, Version, VersionRange, VersionList)
    basic_vers = (Version, CommitVersion)
    ta, tb = type(a), type(b)

    def check_type(t):
        if t not in order:
            raise TypeError("coerce_versions cannot be called on %s" % t)
    check_type(ta)
    check_type(tb)

    if ta == tb or (ta in basic_vers and tb in basic_vers):
        return (a, b)
    elif order.index(ta) > order.index(tb):
        if ta == VersionRange:
            return (a, VersionRange(b, b))
        else:
            return (a, VersionList([b]))
    else:
        if tb == VersionRange:
            return (VersionRange(a, a), b)
        else:
            return (VersionList([a]), b)


def coerced(method):
    """Decorator that ensures that argument types of a method are coerced."""
    @wraps(method)
    def coercing_method(a, b, *args, **kwargs):
        ta = type(a)
        tb = type(b)
        if ta == tb or a is None or b is None or (ta in (Version, CommitVersion) and tb in (Version, CommitVersion)):
            return method(a, b, *args, **kwargs)
        else:
            ca, cb = coerce_versions(a, b)
            return getattr(ca, method.__name__)(cb, *args, **kwargs)
    return coercing_method


class VersionStrComponent(object):
    # NOTE: this is intentionally not a UserString, the abc instanceof
    #       check is slow enough to eliminate all gains
    __slots__ = ['inf_ver', 'data']

    def __init__(self, string):
        self.inf_ver = None
        self.data = string
        if len(string) >= iv_min_len:
            try:
                self.inf_ver = infinity_versions.index(string)
            except ValueError:
                pass

    def __hash__(self):
        return hash(self.data)

    def __str__(self):
        return self.data

    def __eq__(self, other):
        if isinstance(other, VersionStrComponent):
            return self.data == other.data
        return self.data == other

    def __lt__(self, other):
        if isinstance(other, VersionStrComponent):
            if self.inf_ver is not None:
                if other.inf_ver is not None:
                    return self.inf_ver > other.inf_ver
                return False
            if other.inf_ver is not None:
                return True

            return self.data < other.data

        if self.inf_ver is not None:
            return False

        # Numbers are always "newer" than letters.
        # This is for consistency with RPM.  See patch
        # #60884 (and details) from bugzilla #50977 in
        # the RPM project at rpm.org.  Or look at
        # rpmvercmp.c if you want to see how this is
        # implemented there.
        if isinstance(other, int):
            return True
        if isinstance(other, float):
            if other == float('inf'):
                return True
            if other == float('-inf'):
                return False

        if isinstance(other, str):
            return self < VersionStrComponent(other)
        # If we get here, it's an unsupported comparison

        raise ValueError("VersionStrComponent can only be compared with itself, "
                         "int and str, not %s: %s < %s" % (type(other).__name__, self, other))

    def __ne__(self, other):
        return not (self == other)

    def __le__(self, other):
        return self == other or self < other

    def __ge__(self, other):
        return not (self < other)

    def __gt__(self, other):
        return not (self == other) and not (self < other)


@lru_cache(maxsize=5000)
def _make_cmp_version_tuple(v, depth=3):
    if isinstance(v, Version):
        tup = v.version
        if depth > 1:
            tup = (tup, tup + (float('inf'),))
        if depth > 2:
            tup = (tup,)
        return tup
    if isinstance(v, (Version, VersionRange, VersionList)):
        v = str(v)
    if isinstance(v, str):
        if ',' in v:
            # VersionList-like 3-levels, always depth 3 (((ver comps),...),...)
            return tuple(_make_cmp_version_tuple(comp, depth=2) for comp in v.split(','))
        if ':' in v:
            # VersionRange-like 2-levels
            s, e = v.split(':')
            start = _make_cmp_version_tuple(s, depth=1) if s is not None else (float('-inf'),)
            end = _make_cmp_version_tuple(e, depth=1) if e is not None else (float('inf'),)
            tup = (start, end + (float('inf'),))  # emulate upper bound being inclusive
            if depth > 2:
                res = (tup,)
            else:
                res = tup
            return res
        # Version-like 1-level
        segments = SEGMENT_REGEX.findall(v)
        tup = tuple(
            int(m[0]) if m[0] else VersionStrComponent(m[1]) for m in segments
        )
        if depth > 1:
            tup = (tup, tup + (float('inf'),))
        if depth > 2:
            tup = (tup,)
        return tup

    if isinstance(v, Sequence):
        return tuple(_make_cmp_version_tuple(comp, 2) for comp in v)


def _version_tup_to_cmp_version(tup):
    return ((tup, tup + (float('inf'),)),)


class VersionBase(object):
    __slots__ = [
        "_cmp_version",
        "commit_lookup",
    ]

    def __init__(self):
        self._cmp_version = None
        self.commit_lookup = None

    def _get_cmp_version(self, commit_lookup=None):
        return self._cmp_version

    def __ne__(self, other):
        return not (self == other)

    def __le__(self, other):
        return self == other or self < other

    def __ge__(self, other):
        return not (self < other)

    def __gt__(self, other):
        return not (self == other) and not (self < other)


class Version(VersionBase):
    """Class to represent versions"""
    __slots__ = [
        "version",
        "offsets",
        "string",
        "is_commit",
        "commit_version",
    ]

    def __new__(cls, string, _no_continue=False):
        string = str(string)
        is_commit = len(string) == 40 and COMMIT_VERSION.match(string)
        if is_commit and not _no_continue:
            return CommitVersion(string, _no_continue=True)
        return super(Version, cls).__new__(cls)

    def __init__(self, string, **kwargs):
        super(Version, self).__init__()
        if not isinstance(string, str):
            string = str(string)

        # preserve the original string, but trimmed.
        string = string.strip()
        self.string = string

        if string and not VALID_VERSION.match(string):
            raise ValueError("Bad characters in version string: %s" % string)

        self.is_commit = False

        # An object that can lookup git commits to compare them to versions
        self.commit_version = None
        segments = list(SEGMENT_REGEX.finditer(string))
        self.version = tuple(
            int(m.group(1)) if m.group(1) else VersionStrComponent(m.group(2)) for m in segments
        )
        self.offsets = [
            (m.start(1) if m.group(1) else m.start(2),m.start(3)) for m in segments
        ]
        # special comparison version tuple, allows direct comparison between Ver, VerRange and VerList
        self._cmp_version = _version_tup_to_cmp_version(self.version)
        # print(self.cmp_version)

    def _lookup_commit(self, other_lookups=None):
        if self.commit_version is not None:
            return self.commit_version

        commit_lookup = self.commit_lookup or other_lookups
        if commit_lookup is None:
            return None

        commit_info = commit_lookup.get(self.string)
        if commit_info is None:
            return None

        prev_version, distance = commit_info

        # Extend previous version by empty component and distance
        # If commit is exactly a known version, no distance suffix
        prev_tuple = Version(prev_version).version if prev_version else ()
        dist_suffix = (VersionStrComponent(''), distance) if distance else ()
        self.commit_version = prev_tuple + dist_suffix
        # if self.commit_version == ():
        #     self.commit_version = (VersionStrComponent('unknown_commit'),)
        return self.commit_version

    def _cmp(self, other_lookups=None):
        if self.is_commit:
            ret = self._lookup_commit(other_lookups)
            if ret is not None:
                return ret

        return self.version

    @property
    def dotted(self):
        """The dotted representation of the version.

        Example:
        >>> version = Version('1-2-3b')
        >>> version.dotted
        Version('1.2.3b')

        Returns:
            Version: The version with separator characters replaced by dots
        """
        return Version(self.string.replace('-', '.').replace('_', '.'))

    @property
    def underscored(self):
        """The underscored representation of the version.

        Example:
        >>> version = Version('1.2.3b')
        >>> version.underscored
        Version('1_2_3b')

        Returns:
            Version: The version with separator characters replaced by
                underscores
        """
        return Version(self.string.replace('.', '_').replace('-', '_'))

    @property
    def dashed(self):
        """The dashed representation of the version.

        Example:
        >>> version = Version('1.2.3b')
        >>> version.dashed
        Version('1-2-3b')

        Returns:
            Version: The version with separator characters replaced by dashes
        """
        return Version(self.string.replace('.', '-').replace('_', '-'))

    @property
    def joined(self):
        """The joined representation of the version.

        Example:
        >>> version = Version('1.2.3b')
        >>> version.joined
        Version('123b')

        Returns:
            Version: The version with separator characters removed
        """
        return Version(
            self.string.replace('.', '').replace('-', '').replace('_', ''))

    def up_to(self, index):
        """The version up to the specified component.

        Examples:
        >>> version = Version('1.23-4b')
        >>> version.up_to(1)
        Version('1')
        >>> version.up_to(2)
        Version('1.23')
        >>> version.up_to(3)
        Version('1.23-4')
        >>> version.up_to(4)
        Version('1.23-4b')
        >>> version.up_to(-1)
        Version('1.23-4')
        >>> version.up_to(-2)
        Version('1.23')
        >>> version.up_to(-3)
        Version('1')

        Returns:
            Version: The first index components of the version
        """
        return self[:index]

    def lowest(self):
        return self

    def highest(self):
        return self

    def isdevelop(self):
        """Triggers on the special case of the `@develop-like` version."""
        for inf in infinity_versions:
            for v in self.version:
                if v == inf:
                    return True

        return False

    def satisfies(self, other):
        """A Version 'satisfies' another if it is at least as specific and has
        a common prefix.  e.g., we want gcc@4.7.3 to satisfy a request for
        gcc@4.7 so that when a user asks to build with gcc@4.7, we can find
        a suitable compiler.
        """
        other_cmp_ver = other._get_cmp_version(self.commit_lookup)
        if not other_cmp_ver:
            # This repicates old behavior
            # when a tuple comes down from other empty, it's supposed to pass
            return True
        self_cmp_ver = self._get_cmp_version(other.commit_lookup)
        res = any(cv[0] <= self_cmp_ver[0][0] <= cv[1] for cv in other_cmp_ver)
        print("ver-sat", self, self_cmp_ver, other, other_cmp_ver, res)
        return res

    def __iter__(self):
        return iter(self.version)

    def __len__(self):
        return len(self.version)

    def __getitem__(self, idx):
        cls = type(self)

        if isinstance(idx, numbers.Integral):
            return self.version[idx]

        elif isinstance(idx, slice):
            segs = self.offsets[idx]
            string_arg = ''
            if segs:
                string_arg = self.string[segs[0][0]:segs[-1][1]]
            if string_arg:
                return cls(string_arg)
            else:
                return Version('')

        message = '{cls.__name__} indices must be integers'
        raise TypeError(message.format(cls=cls))

    def __repr__(self):
        return 'Version(' + repr(self.string) + ')'

    def __str__(self):
        return self.string

    def __format__(self, format_spec):
        return self.string.format(format_spec)

    @property
    def concrete(self):
        return self

    def __lt__(self, other):
        """Version comparison is designed for consistency with the way RPM
           does things.  If you need more complicated versions in installed
           packages, you should override your package's version string to
           express it more sensibly.
        """
        if other is None:
            return False

        # print(self, self.cmp_version, other, other.cmp_version)
        # Use tuple comparison assisted by VersionStrComponent for performance
        return self._cmp_version < other._get_cmp_version(self.commit_lookup)

    def __eq__(self, other):

        # Cut out early if we don't have a version
        if other is None:
            return False

        # print("eq:",self, self.cmp_version, other, other.cmp_version)
        return self._cmp_version == other._get_cmp_version(self.commit_lookup)

    def __hash__(self):
        return hash(self.version)

    @coerced
    def __contains__(self, other):
        if other is None:
            return False

        if other.is_commit:
            self_cmp = self._cmp(other.commit_lookup)
            return other._cmp(self.commit_lookup)[:len(self_cmp)] == self_cmp

        res = other.version[:len(self.version)] == self.version
        # print('contains', self, self.version, other, other.version, res)
        return res

    def is_predecessor(self, other):
        """True if the other version is the immediate predecessor of this one.
           That is, NO non-commit versions v exist such that:
           (self < v < other and v not in self).
        """
        if other.is_commit:
            return not other.is_successor(self)

        if self.version[:-1] != other.version[:-1]:
            return False

        sl = self.version[-1]
        ol = other.version[-1]
        return type(sl) == int and type(ol) == int and (ol - sl == 1)

    def is_successor(self, other):
        return other.is_predecessor(self)

    @coerced
    def overlaps(self, other):
        return self in other or other in self

    @coerced
    def union(self, other):
        if self == other or other in self:
            return self
        elif self in other:
            return other
        else:
            return VersionList([self, other])

    @coerced
    def intersection(self, other):
        if self in other:  # also covers `self == other`
            return self
        elif other in self:
            return other
        else:
            return VersionList()

    def generate_commit_lookup(self, pkg_name):
        """
        Use the git fetcher to look up a version for a commit.

        Since we want to optimize the clone and lookup, we do the clone once
        and store it in the user specified git repository cache. We also need
        context of the package to get known versions, which could be tags if
        they are linked to Git Releases. If we are unable to determine the
        context of the version, we cannot continue. This implementation is
        alongside the GitFetcher because eventually the git repos cache will
        be one and the same with the source cache.

        Args:
            fetcher: the fetcher to use.
            versions: the known versions of the package
        """

        # Sanity check we have a commit
        if not self.is_commit:
            tty.die("%s is not a commit." % self)

        # Generate a commit looker-upper
        self.commit_lookup = CommitLookup(pkg_name)


class CommitVersion(Version):
    __slots__ = [
        "_cmp_version",
    ]

    def __init__(self, string, **kwargs):
        super().__init__(string)
        self.is_commit = True
        self._cmp_version = None

    def _get_cmp_version(self, commit_lookup=None):
        commit_lookup = None
        if self.commit_version is not None and self._cmp_version is not None:
            return self._cmp_version
        lc = self._lookup_commit(commit_lookup)
        if lc is not None:
            if lc == ():
                self._cmp_version = (((float('-inf'),),(float('inf'),)),)
            else:
                self._cmp_version = _version_tup_to_cmp_version(self.commit_version)
            return self._cmp_version
        # lookup failed,
        if self._cmp_version is None:
            self._cmp_version = _version_tup_to_cmp_version(self.version)
        return self._cmp_version

    def __lt__(self, other):
        """Version comparison is designed for consistency with the way RPM
           does things.  If you need more complicated versions in installed
           packages, you should override your package's version string to
           express it more sensibly.
        """
        if other is None:
            return False

        # print(self, self.cmp_version, other, other.cmp_version)
        # Use tuple comparison assisted by VersionStrComponent for performance
        return self._get_cmp_version(other.commit_lookup) < other._get_cmp_version(self.commit_lookup)

    def __eq__(self, other):

        # Cut out early if we don't have a version
        if other is None:
            return False

        # print("eq:",self, self.cmp_version, other, other.cmp_version)
        return self._get_cmp_version(other.commit_lookup) == other._get_cmp_version(self.commit_lookup)

    def __hash__(self):
        return hash(self.version)

    @coerced
    def __contains__(self, other):
        if other is None:
            return False

        self_cmp = self._cmp(other.commit_lookup)
        return other._cmp(self.commit_lookup)[:len(self_cmp)] == self_cmp

    def is_predecessor(self, other):
        """True if the other version is the immediate predecessor of this one.
           That is, NO non-commit versions v exist such that:
           (self < v < other and v not in self).
        """
        self_cmp = self._cmp(self.commit_lookup)
        other_cmp = other._cmp(other.commit_lookup)

        if self_cmp[:-1] != other_cmp[:-1]:
            return False

        sl = self_cmp[-1]
        ol = other_cmp[-1]
        return type(sl) == int and type(ol) == int and (ol - sl == 1)




class VersionRange(VersionBase):

    def __init__(self, start, end):
        super(VersionRange, self).__init__()
        self.is_commit = False
        if isinstance(start, string_types):
            start = Version(start)
        if isinstance(end, string_types):
            end = Version(end)

        self.start = start
        self.end = end
        self._cmp_version = self._versions_to_cmp_versionrange()

        # Unbounded ranges are not empty
        if not start or not end:
            return

        # Do not allow empty ranges. We have to be careful about lexicographical
        # ordering of versions here: 1.2 < 1.2.3 lexicographically, but 1.2.3:1.2
        # means the range [1.2.3, 1.3), which is non-empty.
        min_len = min(len(start), len(end))
        if end.up_to(min_len) < start.up_to(min_len):
            raise ValueError("Invalid Version range: %s" % self)

    def _versions_to_cmp_versionrange(self):
        if self.start is not None:
            if type(self.start) == CommitVersion:
                # must preserve CommitVersion type inside cmp_version
                s = self.start
            else:
                s = self.start._cmp_version[0][0]
        else:
            s = (float('-inf'),)
        if self.end is not None:
            if type(self.end) == CommitVersion:
                # must preserve CommitVersion type inside cmp_version
                e = self.end
            else:
                e = self.end._cmp_version[0][1]
        else:
            e = (float('-inf'),)

        return ((s, e),)

    def lowest(self):
        return self.start

    def highest(self):
        return self.end

    def __lt__(self, other):
        """Sort VersionRanges lexicographically so that they are ordered first
           by start and then by end.  None denotes an open range, so None in
           the start position is less than everything except None, and None in
           the end position is greater than everything but None.
        """
        if other is None:
            return False

        # print(self._cmp_version , other._get_cmp_version(self.commit_lookup))
        return self._cmp_version < other._get_cmp_version(self.commit_lookup)

    def __eq__(self, other):
        if other is None:
            return False
        # print("range eq:",self, self.cmp_version, other, other.cmp_version)
        return self._cmp_version == other._get_cmp_version(self.commit_lookup)

    def __ne__(self, other):
        return not (self == other)

    def __le__(self, other):
        return self == other or self < other

    def __ge__(self, other):
        return not (self < other)

    def __gt__(self, other):
        return not (self == other) and not (self < other)

    @property
    def concrete(self):
        return self.start if self.start == self.end else None

    @coerced
    def __contains__(self, other):
        if other is None:
            return False

        in_lower = (self.start == other.start or
                    self.start is None or
                    (other.start is not None and (
                        self.start < other.start or
                        other.start in self.start)))
        if not in_lower:
            return False

        in_upper = (self.end == other.end or
                    self.end is None or
                    (other.end is not None and (
                        self.end > other.end or
                        other.end in self.end)))
        return in_upper

    @coerced
    def satisfies(self, other):
        """
        x.satisfies(y) in general means that x and y have a
        non-zero intersection. For VersionRange this means they overlap.

        `satisfies` is a commutative binary operator, meaning that
        x.satisfies(y) if and only if y.satisfies(x).

        Note: in some cases we have the keyword x.satisfies(y, strict=True)
        to mean strict set inclusion, which is not commutative. However, this
        lacks in VersionRange for unknown reasons.

        Examples
        - 1:3 satisfies 2:4, as their intersection is 2:3.
        - 1:2 does not satisfy 3:4, as their intersection is empty.
        - 4.5:4.7 satisfies 4.7.2:4.8, as their intersection is 4.7.2:4.7
        """
        return self.overlaps(other)

    @coerced
    def overlaps(self, other):
        return ((self.start is None or other.end is None or
                 self.start <= other.end or
                 other.end in self.start or self.start in other.end) and
                (other.start is None or self.end is None or
                 other.start <= self.end or
                 other.start in self.end or self.end in other.start))

    @coerced
    def union(self, other):
        if not self.overlaps(other):
            if (self.end is not None and other.start is not None and
                    self.end.is_predecessor(other.start)):
                return VersionRange(self.start, other.end)

            if (other.end is not None and self.start is not None and
                    other.end.is_predecessor(self.start)):
                return VersionRange(other.start, self.end)

            return VersionList([self, other])

        # if we're here, then we know the ranges overlap.
        if self.start is None or other.start is None:
            start = None
        else:
            start = self.start
            # TODO: See note in intersection() about < and in discrepancy.
            if self.start in other.start or other.start < self.start:
                start = other.start

        if self.end is None or other.end is None:
            end = None
        else:
            end = self.end
            # TODO: See note in intersection() about < and in discrepancy.
            if other.end not in self.end:
                if end in other.end or other.end > self.end:
                    end = other.end

        return VersionRange(start, end)

    @coerced
    def intersection(self, other):
        if self.overlaps(other):
            if self.start is None:
                start = other.start
            else:
                start = self.start
                if other.start is not None:
                    if other.start > start or other.start in start:
                        start = other.start

            if self.end is None:
                end = other.end
            else:
                end = self.end
                # TODO: does this make sense?
                # This is tricky:
                #     1.6.5 in 1.6 = True  (1.6.5 is more specific)
                #     1.6 < 1.6.5  = True  (lexicographic)
                # Should 1.6 NOT be less than 1.6.5?  Hmm.
                # Here we test (not end in other.end) first to avoid paradox.
                if other.end is not None and end not in other.end:
                    if other.end < end or other.end in end:
                        end = other.end

            return VersionRange(start, end)

        else:
            return VersionList()

    def __hash__(self):
        return hash((self.start, self.end))

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        out = ""
        if self.start:
            out += str(self.start)
        out += ":"
        if self.end:
            out += str(self.end)
        return out


class VersionList(VersionBase):
    """Sorted, non-redundant list of Versions and VersionRanges."""

    def __init__(self, vlist=None):
        super(VersionList, self).__init__()
        self.is_commit = False
        self.versions = []
        if vlist is not None:
            if isinstance(vlist, string_types):
                vlist = _string_to_version(vlist)
                if type(vlist) == VersionList:
                    self.versions = vlist.versions
                else:
                    self.versions = [vlist]
            else:
                for v in vlist:
                    self._add(ver(v))
            self._cmp_version = self._generate_cmp_ver()
        else:
            self._cmp_version = _make_cmp_version_tuple(':')
        # print(self.cmp_version)

    def _generate_cmp_ver(self):
        cmp_ver = []
        for i, v in enumerate(self.versions):
            # If it's not a CommitVersion, it's a Version or VersionRange
            if type(v) != CommitVersion:
                cmp_ver.extend(v._cmp_version)

        return tuple(cmp_ver)

    def add(self, version):
        self._add(version)

    def _add(self, version, defer_update=False):
        if isinstance(version, (Version, VersionRange)):
            # This normalizes single-value version ranges.
            if version.concrete:
                version = version.concrete

            i = bisect_left(self, version)

            while i - 1 >= 0 and version.overlaps(self[i - 1]):
                version = version.union(self[i - 1])
                del self.versions[i - 1]
                i -= 1

            while i < len(self) and version.overlaps(self[i]):
                version = version.union(self[i])
                del self.versions[i]

            self.versions.insert(i, version)

        elif type(version) == VersionList:
            for v in version:
                self._add(v, defer_update)

        else:
            raise TypeError("Can't add %s to VersionList" % type(version))
        if not defer_update:
            self._cmp_version = self._generate_cmp_ver()

    @property
    def concrete(self):
        if len(self) == 1:
            return self[0].concrete
        else:
            return None

    def copy(self):
        return VersionList(self)

    def lowest(self):
        """Get the lowest version in the list."""
        if not self:
            return None
        else:
            return self[0].lowest()

    def highest(self):
        """Get the highest version in the list."""
        if not self:
            return None
        else:
            return self[-1].highest()

    def highest_numeric(self):
        """Get the highest numeric version in the list."""
        numeric_versions = list(filter(
            lambda v: str(v) not in infinity_versions,
            self.versions))
        if not any(numeric_versions):
            return None
        else:
            return numeric_versions[-1].highest()

    def preferred(self):
        """Get the preferred (latest) version in the list."""
        latest = self.highest_numeric()
        if latest is None:
            latest = self.highest()
        return latest

    @coerced
    def overlaps(self, other):
        if not other or not self:
            return False

        s = o = 0
        while s < len(self) and o < len(other):
            if self[s].overlaps(other[o]):
                return True
            elif self[s] < other[o]:
                s += 1
            else:
                o += 1
        return False

    def to_dict(self):
        """Generate human-readable dict for YAML."""
        if self.concrete:
            return syaml_dict([
                ('version', str(self[0]))
            ])
        else:
            return syaml_dict([
                ('versions', [str(v) for v in self])
            ])

    @staticmethod
    def from_dict(dictionary):
        """Parse dict from to_dict."""
        if 'versions' in dictionary:
            return VersionList(dictionary['versions'])
        elif 'version' in dictionary:
            return VersionList([dictionary['version']])
        else:
            raise ValueError("Dict must have 'version' or 'versions' in it.")

    @coerced
    def satisfies(self, other, strict=False):
        """A VersionList satisfies another if some version in the list
           would satisfy some version in the other list.  This uses
           essentially the same algorithm as overlaps() does for
           VersionList, but it calls satisfies() on member Versions
           and VersionRanges.

           If strict is specified, this version list must lie entirely
           *within* the other in order to satisfy it.
        """
        if not other or not self:
            return False

        if strict:
            return self in other

        s = o = 0
        while s < len(self) and o < len(other):
            if self[s].satisfies(other[o]):
                return True
            elif self[s] < other[o]:
                s += 1
            else:
                o += 1
        return False

    @coerced
    def update(self, other):
        for v in other.versions:
            self._add(v, defer_update=True)
        self._cmp_version = self._generate_cmp_ver()

    @coerced
    def union(self, other):
        result = self.copy()
        result.update(other)
        return result

    @coerced
    def intersection(self, other):
        # TODO: make this faster.  This is O(n^2).
        result = VersionList()
        for s in self:
            for o in other:
                result.add(s.intersection(o))
        return result

    @coerced
    def intersect(self, other):
        """Intersect this spec's list with other.

        Return True if the spec changed as a result; False otherwise
        """
        isection = self.intersection(other)
        changed = (isection.versions != self.versions)
        self.versions = isection.versions
        self._cmp_version = self._generate_cmp_ver()
        return changed

    @coerced
    def __contains__(self, other):
        if len(self) == 0:
            return False

        for version in other:
            i = bisect_left(self, other)
            if i == 0:
                if version not in self[0]:
                    return False
            elif all(version not in v for v in self[i - 1:]):
                return False

        return True

    def __getitem__(self, index):
        return self.versions[index]

    def __iter__(self):
        return iter(self.versions)

    def __reversed__(self):
        return reversed(self.versions)

    def __len__(self):
        return len(self.versions)

    def __bool__(self):
        return bool(self.versions)

    def __eq__(self, other):
        if other is None:
            return False
        return self._cmp_version == other._get_cmp_version(self.commit_lookup)

    def __ne__(self, other):
        return not (self == other)

    def __lt__(self, other):
        if other is None:
            return False

        return self._cmp_version < other._get_cmp_version(self.commit_lookup)

    def __le__(self, other):
        return self == other or self < other

    def __ge__(self, other):
        return not (self < other)

    def __gt__(self, other):
        return not (self == other) and not (self < other)

    def __hash__(self):
        return hash(tuple(self.versions))

    def __str__(self):
        return ",".join(str(v) for v in self.versions)

    def __repr__(self):
        return str(self.versions)


def _string_to_version(string):
    """Converts a string to a Version, VersionList, or VersionRange.
       This is private.  Client code should use ver().
    """
    string = string.replace(' ', '')

    if ',' in string:
        return VersionList(string.split(','))

    elif ':' in string:
        s, e = string.split(':')
        start = Version(s) if s else None
        end = Version(e) if e else None
        return VersionRange(start, end)

    else:
        return Version(string)


def ver(obj):
    """Parses a Version, VersionRange, or VersionList from a string
       or list of strings.
    """
    if isinstance(obj, (list, tuple)):
        return VersionList(obj)
    elif isinstance(obj, string_types):
        return _string_to_version(obj)
    elif isinstance(obj, (int, float)):
        return _string_to_version(str(obj))
    elif type(obj) in (CommitVersion, Version, VersionRange, VersionList):
        return obj
    else:
        raise TypeError("ver() can't convert %s to version!" % type(obj))


class VersionError(spack.error.SpackError):
    """This is raised when something is wrong with a version."""


class VersionChecksumError(VersionError):
    """Raised for version checksum errors."""


class VersionLookupError(VersionError):
    """Raised for errors looking up git commits as versions."""


class CommitLookup(object):
    """An object for cached lookups of git commits

    CommitLookup objects delegate to the misc_cache for locking.
    CommitLookup objects may be attached to a Version object for which
    Version.is_commit returns True to allow for comparisons between git commits
    and versions as represented by tags in the git repository.
    """
    def __init__(self, pkg_name):
        self.pkg_name = pkg_name

        self.data = {}

        self._pkg = None
        self._fetcher = None
        self._cache_key = None
        self._cache_path = None

    # The following properties are used as part of a lazy reference scheme
    # to avoid querying the package repository until it is necessary (and
    # in particular to wait until after the configuration has been
    # assembled)
    @property
    def cache_key(self):
        if not self._cache_key:
            key_base = 'git_metadata'
            if not self.repository_uri.startswith('/'):
                key_base += '/'
            self._cache_key = key_base + self.repository_uri

            # Cache data in misc_cache
            # If this is the first lazy access, initialize the cache as well
            spack_caches().misc_cache.init_entry(self.cache_key)
        return self._cache_key

    @property
    def cache_path(self):
        if not self._cache_path:
            self._cache_path = spack_caches().misc_cache.cache_path(
                self.cache_key)
        return self._cache_path

    @property
    def pkg(self):
        if not self._pkg:
            self._pkg = spack.repo.get(self.pkg_name)
        return self._pkg

    @property
    def fetcher(self):
        if not self._fetcher:
            # We require the full git repository history
            import spack.fetch_strategy  # break cycle
            fetcher = spack.fetch_strategy.GitFetchStrategy(git=self.pkg.git)
            fetcher.get_full_repo = True
            self._fetcher = fetcher
        return self._fetcher

    @property
    def repository_uri(self):
        """
        Identifier for git repos used within the repo and metadata caches.

        """
        try:
            components = [str(c).lstrip('/')
                          for c in spack.util.url.parse_git_url(self.pkg.git)
                          if c]
            return os.path.join(*components)
        except ValueError:
            # If it's not a git url, it's a local path
            return os.path.abspath(self.pkg.git)

    def save(self):
        """
        Save the data to file
        """
        with spack_caches().misc_cache.write_transaction(self.cache_key) as (old, new):
            sjson.dump(self.data, new)

    def load_data(self):
        """
        Load data if the path already exists.
        """
        if os.path.isfile(self.cache_path):
            with spack_caches().misc_cache.read_transaction(self.cache_key) as cache_file:
                self.data = sjson.load(cache_file)

    def get(self, commit):
        if not self.data:
            self.load_data()

        if commit not in self.data:
            self.data[commit] = self.lookup_commit(commit)
            self.save()

        return self.data[commit]

    def lookup_commit(self, commit):
        """Lookup the previous version and distance for a given commit.

        We use git to compare the known versions from package to the git tags,
        as well as any git tags that are SEMVER versions, and find the latest
        known version prior to the commit, as well as the distance from that version
        to the commit in the git repo. Those values are used to compare Version objects.
        """
        dest = os.path.join(spack.paths.user_repos_cache_path, self.repository_uri)
        if dest.endswith('.git'):
            dest = dest[:-4]

        # prepare a cache for the repository
        dest_parent = os.path.dirname(dest)
        if not os.path.exists(dest_parent):
            mkdirp(dest_parent)

        # Only clone if we don't have it!
        if not os.path.exists(dest):
            self.fetcher.clone(dest, bare=True)

        # Lookup commit info
        with working_dir(dest):
            # TODO: we need to update the local tags if they changed on the
            # remote instance, simply adding '-f' may not be sufficient
            # (if commits are deleted on the remote, this command alone
            # won't properly update the local rev-list)
            self.fetcher.git("fetch", '--tags')

            # Ensure commit is an object known to git
            # Note the brackets are literals, the commit replaces the format string
            # This will raise a ProcessError if the commit does not exist
            # We may later design a custom error to re-raise
            self.fetcher.git('cat-file', '-e', '%s^{commit}' % commit)

            # List tags (refs) by date, so last reference of a tag is newest
            tag_info = self.fetcher.git(
                "for-each-ref", "--sort=creatordate", "--format",
                "%(objectname) %(refname)", "refs/tags", output=str).split('\n')

            # Lookup of commits to spack versions
            commit_to_version = {}

            for entry in tag_info:
                if not entry:
                    continue
                tag_commit, tag = entry.split()
                tag = tag.replace('refs/tags/', '', 1)

                # For each tag, try to match to a version
                for v in [v.string for v in self.pkg.versions]:
                    if v == tag or 'v' + v == tag:
                        commit_to_version[tag_commit] = v
                        break
                else:
                    # try to parse tag to copare versions spack does not know
                    match = SEMVER_REGEX.match(tag)
                    if match:
                        semver = match.groupdict()['semver']
                        commit_to_version[tag_commit] = semver

            ancestor_commits = []
            for tag_commit in commit_to_version:
                self.fetcher.git(
                    'merge-base', '--is-ancestor', tag_commit, commit,
                    ignore_errors=[1])
                if self.fetcher.git.returncode == 0:
                    distance = self.fetcher.git(
                        'rev-list', '%s..%s' % (tag_commit, commit), '--count',
                        output=str, error=str).strip()
                    ancestor_commits.append((tag_commit, int(distance)))

            # Get nearest ancestor that is a known version
            ancestor_commits.sort(key=lambda x: x[1])
            if ancestor_commits:
                prev_version_commit, distance = ancestor_commits[0]
                prev_version = commit_to_version[prev_version_commit]
            else:
                # Get list of all commits, this is in reverse order
                # We use this to get the first commit below
                commit_info = self.fetcher.git("log", "--all", "--pretty=format:%H",
                                               output=str)
                commits = [c for c in commit_info.split('\n') if c]

                # No previous version and distance from first commit
                prev_version = None
                distance = int(self.fetcher.git(
                    'rev-list', '%s..%s' % (commits[-1], commit), '--count',
                    output=str, error=str
                ).strip())

        return prev_version, distance
