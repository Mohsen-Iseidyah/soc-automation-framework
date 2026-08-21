// n8n Code node: Check if Alert is made or not

const item = $json;

// فحص قاطع: هل التنبيه مرفوض من TheHive (يحتوي على خطأ) أو لا يمتلك ID؟
if (item.error || !item._id) {
    // إرجاع مصفوفة فارغة يجعل n8n يوقف هذا المسار بصمت تام! 
    // لن يظهر لون أحمر، ولن تنتقل البيانات للخطوة التالية.
    return [];
}

// أما إذا كان التنبيه سليماً وناجحاً، مرره للخطوة التالية
return [{ json: item }];