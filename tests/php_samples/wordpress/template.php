<?php
/* Theme template using alternative syntax and short echo tags. */
$query = $_GET['s'];
?>
<div class="results">
<?php if (!empty($query)) : ?>
    <h1>Results for <?= $query ?></h1>                       <!-- VULN xss via short echo tag -->
    <h2>Results for <?= esc_html($query) ?></h2>              <!-- SAFE -->
<?php elseif (isset($_GET['tag'])) : ?>
    <p>Tag: <?php echo $_GET['tag']; ?></p>                   <!-- VULN xss in elseif colon block -->
<?php else : ?>
    <p>No query</p>
<?php endif; ?>

<?php foreach ($_POST['items'] as $item) : ?>
    <li><?php echo esc_html($item); ?></li>                   <!-- SAFE -->
    <li><?php echo $item; ?></li>                             <!-- VULN xss -->
<?php endforeach; ?>

<?php while (have_posts()) : the_post(); ?>
    <?php if ($_GET['debug']) print $_GET['debug']; ?>        <!-- VULN xss, single-statement if -->
<?php endwhile; ?>
</div>
