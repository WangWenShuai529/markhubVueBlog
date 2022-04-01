<template>
  <div id="app">
	  <!-- 本质就是展现，根据路由展现对应的界面 -->
	  <!-- 实质上是单页 -->
    <router-view/>
  </div>
</template>

<style>
  #app {
    max-width: 960px;
    margin: 0 auto;
  }
</style>
