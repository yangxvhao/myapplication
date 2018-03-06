package com.example.yangxvhao.myapplication;

import android.util.Base64;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * @author yangxvhao
 * @date 17-12-6.
 */

public class HookToast implements IXposedHookLoadPackage {

    private static volatile boolean flag = false;

    private void hook_method(String className, ClassLoader classLoader, String methodName,
                             Object... parameterTypesAndCallback){
        try {
            XposedHelpers.findAndHookMethod(className, classLoader, methodName, parameterTypesAndCallback);
        } catch (Exception e) {
            XposedBridge.log(e);
        }
    }

    private void hook_methods(Class clazz, String methodName, XC_MethodHook xmh){
        try {
            XposedBridge.hookAllMethods(clazz, methodName, xmh);
        } catch (Exception e) {
            XposedBridge.log(e);
        }
    }

    private void hook_methods(String className, String methodName, XC_MethodHook xmh){
        try {
            Class<?> clazz = Class.forName(className);
            XposedBridge.hookAllMethods(clazz, methodName, xmh);
        } catch (Exception e) {
            XposedBridge.log(e);
        }
    }

    private void hookAllConstructors(String className, XC_MethodHook xmh){
        try {
            Class<?> clazz = Class.forName(className);
            XposedBridge.hookAllConstructors(clazz, xmh);
        } catch (Exception e) {
            XposedBridge.log(e);
        }
    }

    @Override
    public void handleLoadPackage(final LoadPackageParam loadPackageParam) throws Throwable {
        XposedBridge.log("66666666666666666666666666" + loadPackageParam.packageName);
        System.out.println("66666666666666666666666666" + loadPackageParam.packageName);
        XC_MethodHook xc_methodHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object result = param.getResult();
                if(result != null && result instanceof String){
                    String str = String.valueOf(result);
                    if(isPhoneNumber(str)) {
                        flag = true;
                        System.out.println("==================6666666666666666=====================");
                    }
                    if(flag){
                        System.out.println(str);
                    }
                }
            }
        };

        hook_methods("java.lang.StringFactory", "newStringFromBytes", xc_methodHook);
        hook_methods("java.lang.StringFactory", "newStringFromChars", xc_methodHook);
        hook_methods("java.lang.StringFactory", "newStringFromStringBuffer", xc_methodHook);
        hook_methods("java.lang.StringFactory", "newStringFromCodePoints", xc_methodHook);
        hook_methods("java.lang.StringFactory", "newStringFromStringBuilder", xc_methodHook);

        hookAllConstructors("javax.crypto.spec.SecretKeySpec", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                System.out.println("key +++++++++++++++++++++++++++++++ " + (param.args == null ? 0 : param.args.length));
                Object result = param.getResult();
                if (param.args != null && param.args.length > 0 && param.args[0] instanceof byte[]){
                    System.out.println("key ------------------------------------ " + new String((byte[])param.args[0]));
                }
                if (param.args != null && param.args.length > 1 && param.args[1] instanceof String){
                    System.out.println("algorithm key------------------------------------ " + param.args[1]);
                }
                if (param.args != null && param.args.length > 3 && param.args[3] instanceof String){
                    System.out.println("algorithm4 key------------------------------------ " + param.args[3]);
                }
            }
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                System.out.println("key +++++++++++++++++++++++++++++++ " + (param.args == null ? 0 : param.args.length));
                Object result = param.getResult();
                if (result != null && result instanceof SecretKeySpec){
                    SecretKeySpec keySpec = (SecretKeySpec) result;
                    System.out.println("key ------------------------------------ " + new String(keySpec.getEncoded()));
                    System.out.println("hex key ------------------------------------ " + encodeHexString(keySpec.getEncoded()));
                    System.out.println("base64 key ------------------------------------ " + Base64.encodeToString(keySpec.getEncoded(), 0));
                }
            }
        });

        hook_methods("javax.crypto.Cipher", "doFinal", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                System.out.println("Cipher key +++++++++++++++++++++++++++++++ " + (param.args == null ? 0 : param.args.length));
                if (param.args != null && param.args.length > 0 && param.args[0] instanceof byte[]){
                    System.out.println("Cipher key ------------------------------------ " + new String((byte[])param.args[0]));
                }
            }
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                System.out.println("Cipher key +++++++++++++++++++++++++++++++ " + (param.args == null ? 0 : param.args.length));
                if (param.args != null && param.args.length > 0 && param.args[0] instanceof byte[]){
                    System.out.println("Cipher key ------------------------------------ " + new String((byte[])param.args[0]));
                }
            }
        });

        hook_methods("javax.crypto.Cipher", "init", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                System.out.println("Cipher init key +++++++++++++++++++++++++++++++ " + (param.args == null ? 0 : param.args.length));
                if (param.args != null){
                    for(Object obj : param.args){
                        if (obj instanceof SecretKeySpec){
                            System.out.println("Cipher SecretKeySpec key ------------------------------------ " + new String(((SecretKeySpec) obj).getEncoded()));
                            System.out.println("Cipher SecretKeySpec hex key ------------------------------------ " + encodeHexString(((SecretKeySpec) obj).getEncoded()));
                            System.out.println("Cipher SecretKeySpec base64 key ------------------------------------ " + Base64.encodeToString(((SecretKeySpec) obj).getEncoded(), 0));
                        }
                        if (obj instanceof IvParameterSpec){
                            byte[] iv = ((IvParameterSpec) obj).getIV();
                            System.out.println("Cipher IvParameterSpec key ------------------------------------ " + new String(iv));
                            System.out.println("Cipher IvParameterSpec base 64 key ------------------------------------ " + Base64.encodeToString(iv, 0));
                            System.out.println("Cipher IvParameterSpec hex key ------------------------------------ " + encodeHexString(iv));
                        }
                        if (obj instanceof SecureRandom){
                            System.out.println("Cipher SecureRandom getAlgorithm key ------------------------------------ " + ((SecureRandom) obj).getAlgorithm());

                            if (((SecureRandom) obj).getProvider() != null){
                                System.out.println("Cipher SecureRandom getProvider key ------------------------------------ " + ((SecureRandom) obj).getProvider().toString());
                            }
                        }
                        System.out.println("Cipher init key ------------------------------------ " + obj.getClass().getName());
                        System.out.println("Cipher init key value------------------------------------ " + String.valueOf(obj));
                    }
                }
            }
        });

        hookAllConstructors("javax.crypto.spec.IvParameterSpec", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args != null && param.args.length > 0 && param.args[0] instanceof byte[]){
                    byte[] iv = (byte[]) param.args[0];
                    System.out.println("Cipher IvParameterSpec key ------------------------------------ " + new String(iv));
                    System.out.println("Cipher IvParameterSpec base64 key ------------------------------------ " + Base64.encodeToString(iv, 0));
                    System.out.println("Cipher IvParameterSpec hex key ------------------------------------ " + encodeHexString(iv));
                }
            }
        });

        hook_methods("java.security.SecureRandom", "setSeed", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                if (param.args != null && param.args.length > 0){
                    if (param.args[0] instanceof byte[]){
                        System.out.println("Cipher setSeed " + new String((byte[])param.args[0]));
                    }else {
                        System.out.println("Cipher setSeed " + param.args[0]);
                    }
                }
            }
        });
    }


    private static final char[] DIGITS_LOWER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final char[] DIGITS_UPPER = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public static char[] encodeHex(byte[] data) {
        return encodeHex(data, true);
    }

    public static char[] encodeHex(byte[] data, boolean toLowerCase) {
        return encodeHex(data, toLowerCase ? DIGITS_LOWER : DIGITS_UPPER);
    }

    protected static char[] encodeHex(byte[] data, char[] toDigits) {
        int l = data.length;
        char[] out = new char[l << 1];
        int i = 0;

        for(int var5 = 0; i < l; ++i) {
            out[var5++] = toDigits[(240 & data[i]) >>> 4];
            out[var5++] = toDigits[15 & data[i]];
        }

        return out;
    }

    public static String encodeHexString(byte[] data) {
        return new String(encodeHex(data));
    }

    public boolean isPhoneNumber(String phone){
        /**
         * 大陆手机号码11位数，匹配格式：前三位固定格式+后8位任意数
         * 此方法中前三位格式有：
         * 13+任意数
         * 15+除4的任意数
         * 18+除1和4的任意数
         * 17+除9的任意数
         * 147
         */
        String phoneRegex = "^((13[0-9])|(15[^4])|(18[0,2,3,5-9])|(17[0-8])|(147))\\d{8}$";
        return Pattern.matches(phoneRegex, phone);
    }

    public static void main(String[] args) {
        System.out.println();
    }
}