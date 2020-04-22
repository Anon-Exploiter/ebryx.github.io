---
layout: default
title : Search
permalink: /search/
show: false

---

<!-- Html Elements for Search -->
<div class="wrapper">
	<div id="search-container">
	<center>
		<div>
			<input class="site-searchbox" type="text" id="keyword" placeholder="Search blog.ebryx.com">
		</div>
		<div>
			<span class="site-searchresults" id="resultbox"></span>
		</div>
	</center>
	</div>
</div>

<!-- Script pointing to search-script.js -->
<script src="/js/search-script.js" type="text/javascript"></script>

<!-- Configuration -->
<script>
SimpleJekyllSearch({
  searchInput: document.getElementById('keyword'),
  resultsContainer: document.getElementById('resultbox'),
  json: '/search.json'
})
</script>